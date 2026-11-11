"""
PPO in plain NumPy (no deep-learning framework needed on the controller host).

Actor  : parameter-shared per-port MLP  [7 port features + 3 global] -> 64 -> 64 -> 3 actions
Critic : centralized MLP on [mean(port features), max(port features), global] -> 64 -> 64 -> 1
Every host port is an agent running the same actor; all ports share the episode reward, so the
advantage of a step is applied to every port's action in that step (shared-reward MAPPO style).

  python ppo_np.py --iters 300 --out ppo_policy.npz
"""
import argparse
import json
import time

import numpy as np

from sim_env import SDNIoTSim, F_PORT, F_GLOB


# ---------------- tiny MLP with manual backprop ----------------
class MLP:
    def __init__(self, sizes, rng, out_scale=0.01):
        self.W, self.b = [], []
        for i, (a, b) in enumerate(zip(sizes[:-1], sizes[1:])):
            s = out_scale if i == len(sizes) - 2 else np.sqrt(1.0 / a)
            self.W.append(rng.normal(0, s, (a, b)).astype(np.float64))
            self.b.append(np.zeros(b))
        self.m = [np.zeros_like(p) for p in self.params()]
        self.v = [np.zeros_like(p) for p in self.params()]
        self.t = 0

    def params(self):
        return self.W + self.b

    def forward(self, x):
        self.cache = [x]
        h = x
        for i in range(len(self.W)):
            h = h @ self.W[i] + self.b[i]
            if i < len(self.W) - 1:
                h = np.tanh(h)
            self.cache.append(h)
        return h

    def backward(self, gout):
        gW, gb = [None] * len(self.W), [None] * len(self.W)
        g = gout
        for i in reversed(range(len(self.W))):
            if i < len(self.W) - 1:
                g = g * (1 - self.cache[i + 1] ** 2)
            gW[i] = self.cache[i].T @ g
            gb[i] = g.sum(0)
            g = g @ self.W[i].T
        return gW + gb

    def adam(self, grads, lr=3e-4, b1=0.9, b2=0.999, eps=1e-8, clip=0.5):
        norm = np.sqrt(sum((g ** 2).sum() for g in grads))
        if norm > clip:
            grads = [g * clip / norm for g in grads]
        self.t += 1
        for k, (p, g) in enumerate(zip(self.params(), grads)):
            self.m[k] = b1 * self.m[k] + (1 - b1) * g
            self.v[k] = b2 * self.v[k] + (1 - b2) * g * g
            mh = self.m[k] / (1 - b1 ** self.t)
            vh = self.v[k] / (1 - b2 ** self.t)
            p -= lr * mh / (np.sqrt(vh) + eps)


def softmax(z):
    z = z - z.max(-1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(-1, keepdims=True)


def actor_in(per, g):
    return np.concatenate([per, np.repeat(g[None], len(per), 0)], 1)


def critic_in(per, g):
    return np.concatenate([per.mean(0), per.max(0), g])[None]


class Agent:
    def __init__(self, seed=0):
        rng = np.random.default_rng(seed)
        self.actor = MLP([F_PORT + F_GLOB, 64, 64, 3], rng)
        self.critic = MLP([2 * F_PORT + F_GLOB, 64, 64, 1], rng, out_scale=1.0)

    def act(self, per, g, greedy=False, rng=None):
        p = softmax(self.actor.forward(actor_in(per, g)))
        if greedy:
            return p.argmax(1), p
        u = rng.random((len(p), 1))
        return (u > np.cumsum(p, 1)).sum(1).clip(0, 2), p

    def value(self, per, g):
        return float(self.critic.forward(critic_in(per, g))[0, 0])

    def save(self, path):
        np.savez(path, **{"aW%d" % i: w for i, w in enumerate(self.actor.W)},
                 **{"ab%d" % i: b for i, b in enumerate(self.actor.b)},
                 **{"cW%d" % i: w for i, w in enumerate(self.critic.W)},
                 **{"cb%d" % i: b for i, b in enumerate(self.critic.b)})

    @staticmethod
    def load(path):
        d = np.load(path)
        ag = Agent()
        ag.actor.W = [d["aW%d" % i] for i in range(3)]
        ag.actor.b = [d["ab%d" % i] for i in range(3)]
        ag.critic.W = [d["cW%d" % i] for i in range(3)]
        ag.critic.b = [d["cb%d" % i] for i in range(3)]
        return ag


class PPOPolicy:
    """Callable policy for evaluation / deployment (greedy)."""
    def __init__(self, path):
        self.ag = Agent.load(path)

    def __call__(self, per, g):
        return self.ag.act(per, g, greedy=True)[0]


# ---------------- training ----------------
def train(iters, n_envs, steps, out, seed, lr=3e-4, clip=0.2, ent=0.01, gamma=0.97, lam=0.95,
          local_w=0.0, init=None):
    rng = np.random.default_rng(seed)
    ag = Agent.load(init) if init else Agent(seed)
    envs = [SDNIoTSim(n_ports=None, seed=seed * 1000 + i) for i in range(n_envs)]
    cur = [e.reset() for e in envs]
    log, t0 = [], time.time()
    for it in range(1, iters + 1):
        steps_buf = []
        for i, e in enumerate(envs):
            seq = []
            for _ in range(steps):
                per, g = cur[i]
                a, p = ag.act(per, g, rng=rng)
                v = ag.value(per, g)
                nobs, r, done, info = e.step(a)
                seq.append(dict(per=per, g=g, a=a, logp=np.log(p[np.arange(len(a)), a] + 1e-12),
                                v=v, r=r, done=done, fail=info["fail"], loc=info["local"]))
                cur[i] = e.reset() if done else nobs
            nv = 0.0 if seq[-1]["done"] else ag.value(*cur[i])
            adv = 0.0
            for s_ in reversed(seq):
                if s_["done"]:
                    nv, adv = 0.0, 0.0
                delta = s_["r"] + gamma * nv - s_["v"]
                adv = delta + gamma * lam * adv
                s_["adv"], s_["ret"] = adv, adv + s_["v"]
                nv = s_["v"]
            steps_buf += seq
        A = np.array([s_["adv"] for s_ in steps_buf])
        A = (A - A.mean()) / (A.std() + 1e-8)
        for s_, a_ in zip(steps_buf, A):
            s_["nadv"] = a_
        idx = np.arange(len(steps_buf))
        for _ in range(4):
            rng.shuffle(idx)
            for k in range(0, len(idx), 48):
                mb = [steps_buf[j] for j in idx[k:k + 48]]
                X = np.concatenate([actor_in(m["per"], m["g"]) for m in mb])
                act = np.concatenate([m["a"] for m in mb])
                old = np.concatenate([m["logp"] for m in mb])
                Am = np.concatenate([m["nadv"] + local_w * m["loc"] for m in mb])   # global + per-port credit
                P = softmax(ag.actor.forward(X))
                logp = np.log(P[np.arange(len(act)), act] + 1e-12)
                ratio = np.exp(logp - old)
                clipped = ((Am > 0) & (ratio > 1 + clip)) | ((Am < 0) & (ratio < 1 - clip))
                g_logp = np.where(clipped, 0.0, -Am * ratio) / len(act)
                onehot = np.eye(3)[act]
                g_z = g_logp[:, None] * (onehot - P)
                H = -(P * np.log(P + 1e-12)).sum(1, keepdims=True)
                g_z += ent * P * (np.log(P + 1e-12) + H) / len(act)
                ag.actor.adam(ag.actor.backward(g_z), lr=lr)
                Xc = np.concatenate([critic_in(m["per"], m["g"]) for m in mb])
                ret = np.array([m["ret"] for m in mb])[:, None]
                V = ag.critic.forward(Xc)
                ag.critic.adam(ag.critic.backward((V - ret) / len(mb)), lr=lr * 3)
        mr = np.mean([s_["r"] for s_ in steps_buf])
        mf = np.mean([s_["fail"] for s_ in steps_buf])
        log.append(dict(iter=it, reward=float(mr), fail=float(mf)))
        if it == 1 or it % 10 == 0:
            print("iter %4d  reward %+.4f  benign-fail %.4f  (%.0f s)" % (it, mr, mf, time.time() - t0), flush=True)
        if it % 25 == 0:
            ag.save(out)
    ag.save(out)
    json.dump(log, open(out.replace(".npz", "_trainlog.json"), "w"))
    return ag


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=300)
    ap.add_argument("--envs", type=int, default=6)
    ap.add_argument("--steps", type=int, default=120)
    ap.add_argument("--out", default="ppo_policy.npz")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--local", type=float, default=0.0, help="weight of per-port credit")
    ap.add_argument("--init", default=None)
    a = ap.parse_args()
    train(a.iters, a.envs, a.steps, a.out, a.seed, local_w=a.local, init=a.init)
