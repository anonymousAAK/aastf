"""PPO-based RL training loop for attack policy refinement.

> **Status: Experimental (research surface).** The pure-Python PPO loop is
> functional and tested, but reward weights, the policy serialization format, and
> the training API may change between minor releases.

Implements Proximal Policy Optimization (pure Python, no external RL
libraries) to evolve attack strategies per ASI category.  The reward
signal combines vulnerability-trigger success, novelty relative to
previously-seen attacks, and a token-cost penalty.

Reward formula::

    reward = vuln_weight * is_vuln_triggered
           + novelty_weight * novelty_score
           - cost_penalty * (token_cost / 1000)
"""

from __future__ import annotations

import logging
import math
import random
from collections import defaultdict
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pydantic configuration models
# ---------------------------------------------------------------------------


class RewardConfig(BaseModel):
    """Knobs for the reward function."""

    vuln_weight: float = 1.0
    novelty_weight: float = 0.3
    cost_penalty: float = 0.1
    novelty_decay: float = 0.95


class PPOConfig(BaseModel):
    """Hyperparameters for the PPO training loop."""

    learning_rate: float = 0.001
    clip_epsilon: float = 0.2
    gamma: float = 0.99
    epochs: int = 10
    batch_size: int = 32
    max_episodes: int = 100


# ---------------------------------------------------------------------------
# Experience / state models
# ---------------------------------------------------------------------------


class Experience(BaseModel):
    """A single (s, a, r, s', done) transition."""

    state: str
    action: str
    reward: float
    next_state: str
    done: bool


class PolicyState(BaseModel):
    """Serialisable snapshot of an :class:`AttackPolicy`."""

    weights: dict[str, float]
    category: str
    generation: int
    avg_reward: float


# ---------------------------------------------------------------------------
# Reward calculator
# ---------------------------------------------------------------------------


class RewardCalculator:
    """Computes per-step reward from vulnerability, novelty, and cost signals."""

    def __init__(self, config: RewardConfig | None = None) -> None:
        self._config = config or RewardConfig()
        self._seen_hashes: set[frozenset[str]] = set()

    # -- public --------------------------------------------------------------

    def compute(
        self,
        vuln_triggered: bool,
        novelty_score: float,
        token_cost: int,
    ) -> float:
        """Return the scalar reward for a single step.

        ``reward = vuln_weight * is_vuln  + novelty_weight * novelty
                 - cost_penalty * (token_cost / 1000)``
        """
        r = (
            self._config.vuln_weight * float(vuln_triggered)
            + self._config.novelty_weight * novelty_score
            - self._config.cost_penalty * (token_cost / 1000)
        )
        return r

    def novelty(self, scenario_text: str, seen_texts: list[str]) -> float:
        """Jaccard *distance* between *scenario_text* and the seen corpus.

        Returns 1.0 when the text is completely novel, 0.0 when identical
        to something already seen.
        """
        if not seen_texts:
            return 1.0

        tokens_new = set(scenario_text.lower().split())
        if not tokens_new:
            return 0.0

        min_similarity = 1.0
        for seen in seen_texts:
            tokens_seen = set(seen.lower().split())
            if not tokens_seen:
                continue
            intersection = len(tokens_new & tokens_seen)
            union = len(tokens_new | tokens_seen)
            similarity = intersection / union if union else 0.0
            min_similarity = min(min_similarity, similarity)

        # We want *maximum* distance (most novel comparison)
        max_distance = 0.0
        for seen in seen_texts:
            tokens_seen = set(seen.lower().split())
            if not tokens_seen:
                max_distance = max(max_distance, 1.0)
                continue
            intersection = len(tokens_new & tokens_seen)
            union = len(tokens_new | tokens_seen)
            similarity = intersection / union if union else 0.0
            distance = 1.0 - similarity
            max_distance = max(max_distance, distance)

        # Use minimum distance (closest match) to determine novelty
        best_sim = 1.0
        for seen in seen_texts:
            tokens_seen = set(seen.lower().split())
            if not tokens_seen:
                continue
            intersection = len(tokens_new & tokens_seen)
            union = len(tokens_new | tokens_seen)
            sim = intersection / union if union else 0.0
            best_sim = min(best_sim, sim)

        # Novelty = 1 - max_similarity (closest match gives highest similarity)
        max_sim = 0.0
        for seen in seen_texts:
            tokens_seen = set(seen.lower().split())
            if not tokens_seen:
                continue
            intersection = len(tokens_new & tokens_seen)
            union = len(tokens_new | tokens_seen)
            sim = intersection / union if union else 0.0
            if sim > max_sim:
                max_sim = sim

        return 1.0 - max_sim


# ---------------------------------------------------------------------------
# Softmax utility
# ---------------------------------------------------------------------------


def _softmax(values: list[float]) -> list[float]:
    """Numerically stable softmax over a list of floats."""
    if not values:
        return []
    max_v = max(values)
    exps = [math.exp(v - max_v) for v in values]
    total = sum(exps)
    if total == 0:
        return [1.0 / len(values)] * len(values)
    return [e / total for e in exps]


# ---------------------------------------------------------------------------
# Attack policy
# ---------------------------------------------------------------------------


class AttackPolicy:
    """Softmax policy over a discrete action space.

    Weights are updated using a clipped PPO-style rule (pure Python).
    """

    def __init__(
        self,
        action_space: list[str],
        seed: int | None = None,
    ) -> None:
        if not action_space:
            raise ValueError("action_space must be non-empty")
        self._action_space = list(action_space)
        self._weights: dict[str, float] = {a: 0.0 for a in action_space}
        self._rng = random.Random(seed)
        self._generation = 0
        self._category = ""
        self._reward_history: list[float] = []

    # -- action selection ----------------------------------------------------

    def select_action(self, state: str) -> str:
        """Sample an action from the softmax distribution.

        The *state* string is hashed to provide a lightweight
        state-dependent bias on top of the learned weights.
        """
        logits = self._state_logits(state)
        probs = _softmax(logits)
        r = self._rng.random()
        cumulative = 0.0
        for i, p in enumerate(probs):
            cumulative += p
            if r <= cumulative:
                return self._action_space[i]
        return self._action_space[-1]

    # -- PPO update ----------------------------------------------------------

    def update(
        self,
        experiences: list[Experience],
        clip_epsilon: float,
        lr: float,
    ) -> None:
        """Apply a clipped PPO-style gradient step from *experiences*.

        For each experience the advantage is approximated as the raw
        reward (no value baseline in this lightweight implementation).
        The weight update is clipped to ``[1 - clip_epsilon, 1 + clip_epsilon]``.
        """
        if not experiences:
            return

        # Accumulate per-action advantage signals
        action_advantages: dict[str, list[float]] = defaultdict(list)
        for exp in experiences:
            action_advantages[exp.action].append(exp.reward)
            self._reward_history.append(exp.reward)

        # Update weights with clipping
        for action, advantages in action_advantages.items():
            if action not in self._weights:
                continue
            mean_adv = sum(advantages) / len(advantages)
            # Compute ratio proxy: clip the effective step
            raw_step = lr * mean_adv
            clipped_step = max(
                -clip_epsilon * lr,
                min(clip_epsilon * lr, raw_step),
            )
            # Use the minimum of raw and clipped (PPO pessimistic bound)
            if mean_adv >= 0:
                step = min(raw_step, clipped_step + lr * clip_epsilon)
            else:
                step = max(raw_step, clipped_step - lr * clip_epsilon)
            self._weights[action] += step

        self._generation += 1

    # -- introspection -------------------------------------------------------

    def action_probabilities(self) -> dict[str, float]:
        """Current softmax probabilities over the action space."""
        logits = [self._weights[a] for a in self._action_space]
        probs = _softmax(logits)
        return dict(zip(self._action_space, probs, strict=True))

    def export(self) -> PolicyState:
        """Serialise the policy to a :class:`PolicyState`."""
        avg_r = (
            sum(self._reward_history) / len(self._reward_history)
            if self._reward_history
            else 0.0
        )
        return PolicyState(
            weights=dict(self._weights),
            category=self._category,
            generation=self._generation,
            avg_reward=round(avg_r, 6),
        )

    def load(self, state: PolicyState) -> None:
        """Restore weights from a :class:`PolicyState`."""
        for action in self._action_space:
            if action in state.weights:
                self._weights[action] = state.weights[action]
        self._generation = state.generation
        self._category = state.category

    # -- private -------------------------------------------------------------

    def _state_logits(self, state: str) -> list[float]:
        """Combine base weights with a lightweight state hash bias."""
        # Simple hash-based feature: distribute state info across actions
        h = hash(state) & 0xFFFFFFFF
        logits: list[float] = []
        for i, action in enumerate(self._action_space):
            base = self._weights[action]
            # Small deterministic perturbation from state
            state_bias = ((h >> (i % 16)) & 0xF) / 160.0 - 0.05
            logits.append(base + state_bias)
        return logits


# ---------------------------------------------------------------------------
# PPO trainer
# ---------------------------------------------------------------------------


class PPOTrainer:
    """Runs the PPO training loop over attack episodes."""

    def __init__(
        self,
        config: PPOConfig | None = None,
        reward_config: RewardConfig | None = None,
        action_space: list[str] | None = None,
    ) -> None:
        self._config = config or PPOConfig()
        self._reward_config = reward_config or RewardConfig()
        self._action_space = action_space or [
            "REPHRASE",
            "CONTEXT_SHIFT",
            "FORMAT_CHANGE",
            "SALIENCE_BOOST",
            "PERSONA_SWAP",
            "SYNONYM",
        ]
        self._reward_calc = RewardCalculator(self._reward_config)
        self._history: list[dict[str, Any]] = []

    # -- episode collection --------------------------------------------------

    def collect_episode(
        self,
        policy: AttackPolicy,
        scenario_fn: Callable[..., dict[str, Any]],
    ) -> list[Experience]:
        """Run one episode by calling *scenario_fn* and collecting transitions.

        *scenario_fn* should accept ``(action: str, step: int)`` and return a
        dict with keys: ``state``, ``next_state``, ``vuln_triggered`` (bool),
        ``novelty_score`` (float), ``token_cost`` (int), ``done`` (bool).
        """
        experiences: list[Experience] = []
        step = 0
        state = "initial"
        done = False

        while not done and step < self._config.batch_size:
            action = policy.select_action(state)
            result = scenario_fn(action=action, step=step)

            reward = self._reward_calc.compute(
                vuln_triggered=result.get("vuln_triggered", False),
                novelty_score=result.get("novelty_score", 0.0),
                token_cost=result.get("token_cost", 0),
            )

            next_state = result.get("next_state", state)
            done = result.get("done", False)

            experiences.append(
                Experience(
                    state=state,
                    action=action,
                    reward=reward,
                    next_state=next_state,
                    done=done,
                )
            )
            state = next_state
            step += 1

        return experiences

    # -- training ------------------------------------------------------------

    def train(self, episodes: list[list[Experience]]) -> AttackPolicy:
        """Full training loop over pre-collected *episodes*.

        Returns the refined :class:`AttackPolicy`.
        """
        policy = AttackPolicy(self._action_space)
        self._history.clear()

        for epoch in range(self._config.epochs):
            epoch_rewards: list[float] = []
            for episode in episodes:
                if not episode:
                    continue
                # Discount rewards
                discounted = self._discount_rewards(
                    [e.reward for e in episode],
                    self._config.gamma,
                )
                # Build discounted experiences
                disc_exps = [
                    Experience(
                        state=e.state,
                        action=e.action,
                        reward=dr,
                        next_state=e.next_state,
                        done=e.done,
                    )
                    for e, dr in zip(episode, discounted, strict=True)
                ]
                policy.update(
                    disc_exps,
                    clip_epsilon=self._config.clip_epsilon,
                    lr=self._config.learning_rate,
                )
                epoch_rewards.extend(discounted)

            avg_reward = (
                sum(epoch_rewards) / len(epoch_rewards) if epoch_rewards else 0.0
            )
            self._history.append(
                {
                    "epoch": epoch,
                    "avg_reward": round(avg_reward, 6),
                    "num_experiences": len(epoch_rewards),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
            logger.debug(
                "PPO epoch %d/%d  avg_reward=%.4f  experiences=%d",
                epoch + 1,
                self._config.epochs,
                avg_reward,
                len(epoch_rewards),
            )

        return policy

    # -- evaluation ----------------------------------------------------------

    def evaluate(
        self,
        policy: AttackPolicy,
        test_scenarios: list[Callable[..., dict[str, Any]]],
    ) -> dict[str, Any]:
        """Evaluate *policy* on a list of scenario functions.

        Returns a dict with ``attack_success_rate``, ``avg_reward``, and
        ``total_episodes``.
        """
        total_rewards: list[float] = []
        successes = 0

        for scenario_fn in test_scenarios:
            episode = self.collect_episode(policy, scenario_fn)
            ep_reward = sum(e.reward for e in episode)
            total_rewards.append(ep_reward)
            # An episode counts as success if any step triggered vulnerability
            if any(e.reward >= self._reward_config.vuln_weight * 0.5 for e in episode):
                successes += 1

        n = len(test_scenarios) if test_scenarios else 1
        return {
            "attack_success_rate": round(successes / n, 4) if n else 0.0,
            "avg_reward": (
                round(sum(total_rewards) / len(total_rewards), 6)
                if total_rewards
                else 0.0
            ),
            "total_episodes": len(test_scenarios),
        }

    def training_history(self) -> list[dict[str, Any]]:
        """Per-epoch metrics from the most recent :meth:`train` call."""
        return list(self._history)

    # -- private -------------------------------------------------------------

    @staticmethod
    def _discount_rewards(rewards: list[float], gamma: float) -> list[float]:
        """Compute discounted returns (backwards through time)."""
        discounted: list[float] = [0.0] * len(rewards)
        running = 0.0
        for t in reversed(range(len(rewards))):
            running = rewards[t] + gamma * running
            discounted[t] = running
        return discounted


# ---------------------------------------------------------------------------
# Category trainer
# ---------------------------------------------------------------------------


class CategoryTrainer:
    """Trains separate :class:`AttackPolicy` instances per ASI category."""

    def __init__(
        self,
        categories: list[str],
        config: PPOConfig | None = None,
        reward_config: RewardConfig | None = None,
        action_space: list[str] | None = None,
    ) -> None:
        self._categories = list(categories)
        self._config = config or PPOConfig()
        self._reward_config = reward_config or RewardConfig()
        self._action_space = action_space or [
            "REPHRASE",
            "CONTEXT_SHIFT",
            "FORMAT_CHANGE",
            "SALIENCE_BOOST",
            "PERSONA_SWAP",
            "SYNONYM",
        ]
        self._policies: dict[str, AttackPolicy] = {}
        self._trainers: dict[str, PPOTrainer] = {}

    # -- single category -----------------------------------------------------

    def train_category(
        self,
        category: str,
        scenario_fn: Callable[..., dict[str, Any]],
    ) -> AttackPolicy:
        """Train a policy for *category* using *scenario_fn*.

        Collects ``max_episodes`` episodes and runs the PPO loop.
        """
        trainer = PPOTrainer(
            config=self._config,
            reward_config=self._reward_config,
            action_space=self._action_space,
        )
        policy = AttackPolicy(self._action_space)
        policy._category = category

        episodes: list[list[Experience]] = []
        for _ in range(self._config.max_episodes):
            ep = trainer.collect_episode(policy, scenario_fn)
            episodes.append(ep)

        trained_policy = trainer.train(episodes)
        trained_policy._category = category
        self._policies[category] = trained_policy
        self._trainers[category] = trainer
        return trained_policy

    # -- all categories ------------------------------------------------------

    def train_all(
        self,
        scenario_fns: dict[str, Callable[..., dict[str, Any]]],
    ) -> dict[str, AttackPolicy]:
        """Train policies for all categories in *scenario_fns*."""
        results: dict[str, AttackPolicy] = {}
        for category, fn in scenario_fns.items():
            if category not in self._categories:
                logger.warning("Category %s not in configured list, skipping", category)
                continue
            results[category] = self.train_category(category, fn)
        return results

    def best_policy(self, category: str) -> AttackPolicy:
        """Return the trained policy for *category*.

        Raises :class:`KeyError` if the category has not been trained.
        """
        if category not in self._policies:
            raise KeyError(
                f"No trained policy for category {category!r}. "
                f"Available: {list(self._policies.keys())}"
            )
        return self._policies[category]
