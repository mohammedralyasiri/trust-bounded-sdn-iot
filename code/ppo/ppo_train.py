"""
PPO with a parameter-shared per-port actor (every host port is an agent running the same small
policy on its own features + global controller context) and a centralized critic.
Trained in the calibrated simulator (sim_env.py); the exported weights are loaded by the controller.

  python ppo_train.py --iters 400 --out ppo_policy.pt
"""
import argparse
import json
import time

import numpy as np
import torch
import torch.nn as nn

from sim_env import SDNIoTSim, F_PORT, F_GLOB


class Actor(nn.Module):
    def __init__(self, h=64):
        super().__init__()
        self.net = nn.Sequential(nn.Linear(F_PORT + F_GLOB, h), nn.Tanh(), nn.Linear(h, h), nn.Tanh(),
                                 nn.Linear(h, 3))

    def forward(self, per, g):                    # per: [B,N,F]  g: [B,G]
        x = torch.cat([per, g.unsqueeze(1).expand(-1, per.shape[1], -1)], -1)
        return self.net(x)                         # [B,N,3]


class Critic(nn.Module):
    def __init__(self, h=64):
        super().__init__()
        self.net = nn.Sequential(nn.Linear(2 * F_PORT + F_GLOB, h), nn.Tanh(), nn.Linear(h, h), nn.Tanh(),
                                 nn.Linear(h, 1))

    def forward(self, per, g):
        x = torch.cat([per.mean(1), per.max(1).values, g], -1)
        return self.net(x).squeeze(-1)


def rollout(envs, actor, critic, steps):
    buf = []
    obs = [e.cur for e in envs]
    for _ in range(steps):
        for i, e in enumerate(envs):
            per, g = obs[i]
            P, G = torch.from_numpy(per)[None], torch.from_numpy(g)[None]
            with torch.no_grad():
                logits = actor(P, G)[0]
                dist = torch.distributions.Categorical(logits=logits)
                a = dist.sample()
                v = critic(P, G)[0]
            nobs, r, done, info = e.step(a.numpy())
            buf.append(dict(env=i, per=per, g=g, a=a.numpy(), logp=dist.log_prob(a).numpy(),
                            v=v.item(), r=r, done=done, fail=info["fail"]))
            if done:
                nobs = e.reset()
            obs[i] = nobs
            e.cur = nobs
    return buf


def gae(buf, envs, critic, gamma=0.97, lam=0.95):
    for i in range(len(envs)):
        seq = [b for b in buf if b["env"] == i]
        per, g = envs[i].cur
        with torch.no_grad():
            nv = critic(torch.from_numpy(per)[None], torch.from_numpy(g)[None]).item()
        adv = 0.0
        for b in reversed(seq):
            if b["done"]:
                nv, adv = 0.0, 0.0
            delta = b["r"] + gamma * nv - b["v"]
            adv = delta + gamma * lam * adv
            b["adv"], b["ret"] = adv, adv + b["v"]
            nv = b["v"]


def update(buf, actor, critic, opt, epochs=4, clip=0.2, ent=0.01):
    adv = np.array([b["adv"] for b in buf], np.float32)
    adv = (adv - adv.mean()) / (adv.std() + 1e-8)
    for b, a_ in zip(buf, adv):
        b["nadv"] = a_
    idx = np.arange(len(buf))
    for _ in range(epochs):
        np.random.shuffle(idx)
        for k in range(0, len(idx), 64):
            mb = [buf[j] for j in idx[k:k + 64]]
            loss = 0.0
            for b in mb:                                       # ports differ per episode -> per-sample
                P = torch.from_numpy(b["per"])[None]
                G = torch.from_numpy(b["g"])[None]
                logits = actor(P, G)[0]
                dist = torch.distributions.Categorical(logits=logits)
                a = torch.from_numpy(b["a"])
                ratio = torch.exp(dist.log_prob(a) - torch.from_numpy(b["logp"]))
                A = torch.tensor(b["nadv"])
                pl = -torch.min(ratio * A, torch.clamp(ratio, 1 - clip, 1 + clip) * A).mean()
                vl = (critic(P, G)[0] - torch.tensor(b["ret"], dtype=torch.float32)) ** 2
                loss = loss + pl + 0.5 * vl - ent * dist.entropy().mean()
            opt.zero_grad()
            (loss / len(mb)).backward()
            nn.utils.clip_grad_norm_(list(actor.parameters()) + list(critic.parameters()), 0.5)
            opt.step()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=300)
    ap.add_argument("--envs", type=int, default=6)
    ap.add_argument("--steps", type=int, default=120)
    ap.add_argument("--out", default="ppo_policy.pt")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    torch.set_num_threads(2)
    envs = [SDNIoTSim(n_ports=None, seed=args.seed * 100 + i) for i in range(args.envs)]
    for e in envs:
        e.cur = e.reset()
    actor, critic = Actor(), Critic()
    opt = torch.optim.Adam(list(actor.parameters()) + list(critic.parameters()), lr=3e-4)
    log = []
    t0 = time.time()
    for it in range(1, args.iters + 1):
        buf = rollout(envs, actor, critic, args.steps)
        gae(buf, envs, critic)
        update(buf, actor, critic, opt)
        mr = np.mean([b["r"] for b in buf])
        mf = np.mean([b["fail"] for b in buf])
        log.append(dict(iter=it, reward=float(mr), fail=float(mf)))
        if it % 10 == 0 or it == 1:
            print("iter %4d  reward %.4f  benign-fail %.4f  (%.0f s)" % (it, mr, mf, time.time() - t0), flush=True)
        if it % 50 == 0:
            torch.save({"actor": actor.state_dict(), "critic": critic.state_dict()}, args.out)
    torch.save({"actor": actor.state_dict(), "critic": critic.state_dict()}, args.out)
    json.dump(log, open(args.out.replace(".pt", "_trainlog.json"), "w"))
    print("saved", args.out)


if __name__ == "__main__":
    main()
