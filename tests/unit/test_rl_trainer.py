"""Tests for the PPO-based RL attack trainer."""

from __future__ import annotations

import pytest

from aastf.rl_trainer import (
    AttackPolicy,
    CategoryTrainer,
    Experience,
    PolicyState,
    PPOConfig,
    PPOTrainer,
    RewardCalculator,
    RewardConfig,
    _softmax,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ACTION_SPACE = ["REPHRASE", "CONTEXT_SHIFT", "FORMAT_CHANGE", "SYNONYM"]


def _simple_scenario_fn(*, action: str, step: int) -> dict:
    """Deterministic scenario that rewards REPHRASE and ends after 3 steps."""
    return {
        "state": f"step-{step}",
        "next_state": f"step-{step + 1}",
        "vuln_triggered": action == "REPHRASE",
        "novelty_score": 0.5,
        "token_cost": 100,
        "done": step >= 2,
    }


def _always_vuln_fn(*, action: str, step: int) -> dict:
    return {
        "state": f"s{step}",
        "next_state": f"s{step + 1}",
        "vuln_triggered": True,
        "novelty_score": 0.8,
        "token_cost": 50,
        "done": step >= 1,
    }


def _never_vuln_fn(*, action: str, step: int) -> dict:
    return {
        "state": f"s{step}",
        "next_state": f"s{step + 1}",
        "vuln_triggered": False,
        "novelty_score": 0.1,
        "token_cost": 200,
        "done": step >= 1,
    }


# ===================================================================
# RewardConfig
# ===================================================================


class TestRewardConfig:
    def test_defaults(self):
        cfg = RewardConfig()
        assert cfg.vuln_weight == 1.0
        assert cfg.novelty_weight == 0.3
        assert cfg.cost_penalty == 0.1
        assert cfg.novelty_decay == 0.95

    def test_custom_values(self):
        cfg = RewardConfig(vuln_weight=2.0, cost_penalty=0.5)
        assert cfg.vuln_weight == 2.0
        assert cfg.cost_penalty == 0.5


# ===================================================================
# PPOConfig
# ===================================================================


class TestPPOConfig:
    def test_defaults(self):
        cfg = PPOConfig()
        assert cfg.learning_rate == 0.001
        assert cfg.clip_epsilon == 0.2
        assert cfg.gamma == 0.99
        assert cfg.epochs == 10
        assert cfg.batch_size == 32
        assert cfg.max_episodes == 100

    def test_custom_values(self):
        cfg = PPOConfig(epochs=5, batch_size=16)
        assert cfg.epochs == 5
        assert cfg.batch_size == 16


# ===================================================================
# Experience
# ===================================================================


class TestExperience:
    def test_creation(self):
        exp = Experience(
            state="s0", action="REPHRASE", reward=1.0, next_state="s1", done=False
        )
        assert exp.state == "s0"
        assert exp.action == "REPHRASE"
        assert exp.reward == 1.0
        assert exp.done is False

    def test_done_terminal(self):
        exp = Experience(
            state="s9", action="SYNONYM", reward=-0.5, next_state="s10", done=True
        )
        assert exp.done is True


# ===================================================================
# PolicyState
# ===================================================================


class TestPolicyState:
    def test_serialisation(self):
        ps = PolicyState(
            weights={"A": 0.1, "B": 0.9},
            category="ASI01",
            generation=5,
            avg_reward=0.42,
        )
        assert ps.category == "ASI01"
        assert ps.generation == 5
        assert ps.weights["A"] == pytest.approx(0.1)

    def test_round_trip_json(self):
        ps = PolicyState(
            weights={"X": 1.0}, category="ASI02", generation=1, avg_reward=0.0
        )
        data = ps.model_dump_json()
        restored = PolicyState.model_validate_json(data)
        assert restored == ps


# ===================================================================
# _softmax
# ===================================================================


class TestSoftmax:
    def test_uniform(self):
        probs = _softmax([0.0, 0.0, 0.0])
        assert len(probs) == 3
        for p in probs:
            assert p == pytest.approx(1.0 / 3, abs=1e-6)

    def test_sums_to_one(self):
        probs = _softmax([1.0, 2.0, 3.0])
        assert sum(probs) == pytest.approx(1.0)

    def test_empty(self):
        assert _softmax([]) == []

    def test_single(self):
        probs = _softmax([5.0])
        assert probs == [pytest.approx(1.0)]

    def test_large_values_stable(self):
        probs = _softmax([1000.0, 1001.0, 1002.0])
        assert sum(probs) == pytest.approx(1.0)
        assert probs[2] > probs[1] > probs[0]


# ===================================================================
# RewardCalculator
# ===================================================================


class TestRewardCalculator:
    def test_vuln_triggered_reward(self):
        calc = RewardCalculator()
        r = calc.compute(vuln_triggered=True, novelty_score=0.0, token_cost=0)
        assert r == pytest.approx(1.0)

    def test_no_vuln_zero_novelty(self):
        calc = RewardCalculator()
        r = calc.compute(vuln_triggered=False, novelty_score=0.0, token_cost=0)
        assert r == pytest.approx(0.0)

    def test_novelty_contribution(self):
        calc = RewardCalculator()
        r = calc.compute(vuln_triggered=False, novelty_score=1.0, token_cost=0)
        assert r == pytest.approx(0.3)

    def test_cost_penalty(self):
        calc = RewardCalculator()
        r = calc.compute(vuln_triggered=False, novelty_score=0.0, token_cost=1000)
        assert r == pytest.approx(-0.1)

    def test_combined(self):
        calc = RewardCalculator()
        r = calc.compute(vuln_triggered=True, novelty_score=0.5, token_cost=500)
        expected = 1.0 + 0.3 * 0.5 - 0.1 * 0.5
        assert r == pytest.approx(expected)

    def test_custom_weights(self):
        cfg = RewardConfig(vuln_weight=2.0, novelty_weight=0.5, cost_penalty=0.2)
        calc = RewardCalculator(cfg)
        r = calc.compute(vuln_triggered=True, novelty_score=1.0, token_cost=1000)
        expected = 2.0 + 0.5 - 0.2
        assert r == pytest.approx(expected)

    def test_novelty_identical_text(self):
        calc = RewardCalculator()
        n = calc.novelty("hello world", ["hello world"])
        assert n == pytest.approx(0.0)

    def test_novelty_completely_different(self):
        calc = RewardCalculator()
        n = calc.novelty("alpha beta", ["gamma delta"])
        assert n == pytest.approx(1.0)

    def test_novelty_partial_overlap(self):
        calc = RewardCalculator()
        n = calc.novelty("hello world foo", ["hello world bar"])
        assert 0.0 < n < 1.0

    def test_novelty_empty_seen(self):
        calc = RewardCalculator()
        n = calc.novelty("anything", [])
        assert n == pytest.approx(1.0)

    def test_novelty_empty_text(self):
        calc = RewardCalculator()
        n = calc.novelty("", ["hello"])
        assert n == pytest.approx(0.0)


# ===================================================================
# AttackPolicy
# ===================================================================


class TestAttackPolicy:
    def test_create(self):
        policy = AttackPolicy(ACTION_SPACE, seed=42)
        probs = policy.action_probabilities()
        assert len(probs) == 4
        assert sum(probs.values()) == pytest.approx(1.0)

    def test_empty_action_space_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            AttackPolicy([])

    def test_select_action_returns_valid(self):
        policy = AttackPolicy(ACTION_SPACE, seed=42)
        for _ in range(20):
            action = policy.select_action("some state")
            assert action in ACTION_SPACE

    def test_select_action_deterministic_with_seed(self):
        p1 = AttackPolicy(ACTION_SPACE, seed=99)
        p2 = AttackPolicy(ACTION_SPACE, seed=99)
        actions1 = [p1.select_action(f"state-{i}") for i in range(10)]
        actions2 = [p2.select_action(f"state-{i}") for i in range(10)]
        assert actions1 == actions2

    def test_update_changes_weights(self):
        policy = AttackPolicy(ACTION_SPACE, seed=42)
        initial = dict(policy._weights)
        exps = [
            Experience(
                state="s", action="REPHRASE", reward=1.0, next_state="s1", done=False
            ),
            Experience(
                state="s", action="REPHRASE", reward=1.0, next_state="s2", done=True
            ),
        ]
        policy.update(exps, clip_epsilon=0.2, lr=0.01)
        assert policy._weights["REPHRASE"] != initial["REPHRASE"]

    def test_update_empty_noop(self):
        policy = AttackPolicy(ACTION_SPACE, seed=42)
        initial = dict(policy._weights)
        policy.update([], clip_epsilon=0.2, lr=0.01)
        assert policy._weights == initial

    def test_export_and_load(self):
        policy = AttackPolicy(ACTION_SPACE, seed=42)
        policy._category = "ASI01"
        exps = [
            Experience(
                state="s", action="SYNONYM", reward=0.5, next_state="s1", done=True
            ),
        ]
        policy.update(exps, clip_epsilon=0.2, lr=0.01)

        state = policy.export()
        assert state.category == "ASI01"
        assert state.generation == 1

        new_policy = AttackPolicy(ACTION_SPACE, seed=0)
        new_policy.load(state)
        assert new_policy._weights == policy._weights
        assert new_policy._generation == 1

    def test_action_probabilities_sum(self):
        policy = AttackPolicy(ACTION_SPACE, seed=42)
        probs = policy.action_probabilities()
        assert sum(probs.values()) == pytest.approx(1.0)

    def test_positive_reward_increases_weight(self):
        policy = AttackPolicy(ACTION_SPACE, seed=42)
        initial_w = policy._weights["REPHRASE"]
        exps = [
            Experience(
                state="s", action="REPHRASE", reward=5.0, next_state="s1", done=True
            )
            for _ in range(5)
        ]
        policy.update(exps, clip_epsilon=0.2, lr=0.1)
        assert policy._weights["REPHRASE"] > initial_w

    def test_negative_reward_decreases_weight(self):
        policy = AttackPolicy(ACTION_SPACE, seed=42)
        initial_w = policy._weights["REPHRASE"]
        exps = [
            Experience(
                state="s", action="REPHRASE", reward=-5.0, next_state="s1", done=True
            )
            for _ in range(5)
        ]
        policy.update(exps, clip_epsilon=0.2, lr=0.1)
        assert policy._weights["REPHRASE"] < initial_w


# ===================================================================
# PPOTrainer
# ===================================================================


class TestPPOTrainer:
    def test_collect_episode(self):
        trainer = PPOTrainer(action_space=ACTION_SPACE)
        policy = AttackPolicy(ACTION_SPACE, seed=42)
        episode = trainer.collect_episode(policy, _simple_scenario_fn)
        assert len(episode) > 0
        assert all(isinstance(e, Experience) for e in episode)
        assert episode[-1].done is True

    def test_collect_episode_respects_done(self):
        trainer = PPOTrainer(action_space=ACTION_SPACE)
        policy = AttackPolicy(ACTION_SPACE, seed=42)
        episode = trainer.collect_episode(policy, _simple_scenario_fn)
        # _simple_scenario_fn ends at step >= 2, so max 3 steps
        assert len(episode) <= 3

    def test_train_returns_policy(self):
        trainer = PPOTrainer(
            config=PPOConfig(epochs=2, batch_size=4),
            action_space=ACTION_SPACE,
        )
        policy = AttackPolicy(ACTION_SPACE, seed=42)
        episodes = [
            trainer.collect_episode(policy, _simple_scenario_fn) for _ in range(3)
        ]
        trained = trainer.train(episodes)
        assert isinstance(trained, AttackPolicy)

    def test_training_history(self):
        trainer = PPOTrainer(
            config=PPOConfig(epochs=3, batch_size=4),
            action_space=ACTION_SPACE,
        )
        policy = AttackPolicy(ACTION_SPACE, seed=42)
        episodes = [
            trainer.collect_episode(policy, _simple_scenario_fn) for _ in range(2)
        ]
        trainer.train(episodes)
        history = trainer.training_history()
        assert len(history) == 3
        assert all("epoch" in h for h in history)
        assert all("avg_reward" in h for h in history)

    def test_evaluate(self):
        trainer = PPOTrainer(action_space=ACTION_SPACE)
        policy = AttackPolicy(ACTION_SPACE, seed=42)
        result = trainer.evaluate(policy, [_always_vuln_fn, _never_vuln_fn])
        assert "attack_success_rate" in result
        assert "avg_reward" in result
        assert "total_episodes" in result
        assert result["total_episodes"] == 2

    def test_evaluate_all_vuln(self):
        trainer = PPOTrainer(action_space=ACTION_SPACE)
        policy = AttackPolicy(ACTION_SPACE, seed=42)
        result = trainer.evaluate(policy, [_always_vuln_fn, _always_vuln_fn])
        assert result["attack_success_rate"] == pytest.approx(1.0)

    def test_evaluate_empty_scenarios(self):
        trainer = PPOTrainer(action_space=ACTION_SPACE)
        policy = AttackPolicy(ACTION_SPACE, seed=42)
        result = trainer.evaluate(policy, [])
        assert result["total_episodes"] == 0

    def test_discount_rewards(self):
        rewards = [1.0, 1.0, 1.0]
        discounted = PPOTrainer._discount_rewards(rewards, gamma=0.99)
        assert len(discounted) == 3
        # First element should be largest (accumulated future rewards)
        assert discounted[0] > discounted[1] > discounted[2]
        assert discounted[2] == pytest.approx(1.0)

    def test_discount_gamma_zero(self):
        rewards = [1.0, 2.0, 3.0]
        discounted = PPOTrainer._discount_rewards(rewards, gamma=0.0)
        assert discounted == [pytest.approx(1.0), pytest.approx(2.0), pytest.approx(3.0)]

    def test_train_improves_vuln_action(self):
        """After training on always-vuln, all actions should see reward."""
        trainer = PPOTrainer(
            config=PPOConfig(epochs=5, batch_size=4, max_episodes=10),
            action_space=ACTION_SPACE,
        )
        policy = AttackPolicy(ACTION_SPACE, seed=42)
        episodes = [
            trainer.collect_episode(policy, _always_vuln_fn) for _ in range(10)
        ]
        trained = trainer.train(episodes)
        state = trained.export()
        assert state.avg_reward > 0

    def test_train_empty_episodes(self):
        trainer = PPOTrainer(
            config=PPOConfig(epochs=2),
            action_space=ACTION_SPACE,
        )
        trained = trainer.train([])
        assert isinstance(trained, AttackPolicy)

    def test_train_with_empty_episode_lists(self):
        trainer = PPOTrainer(
            config=PPOConfig(epochs=2),
            action_space=ACTION_SPACE,
        )
        trained = trainer.train([[], []])
        assert isinstance(trained, AttackPolicy)


# ===================================================================
# CategoryTrainer
# ===================================================================


class TestCategoryTrainer:
    def test_train_category(self):
        ct = CategoryTrainer(
            categories=["ASI01", "ASI02"],
            config=PPOConfig(epochs=2, batch_size=4, max_episodes=3),
            action_space=ACTION_SPACE,
        )
        policy = ct.train_category("ASI01", _simple_scenario_fn)
        assert isinstance(policy, AttackPolicy)
        assert policy._category == "ASI01"

    def test_best_policy(self):
        ct = CategoryTrainer(
            categories=["ASI01"],
            config=PPOConfig(epochs=2, batch_size=4, max_episodes=3),
            action_space=ACTION_SPACE,
        )
        ct.train_category("ASI01", _simple_scenario_fn)
        best = ct.best_policy("ASI01")
        assert isinstance(best, AttackPolicy)

    def test_best_policy_missing_raises(self):
        ct = CategoryTrainer(categories=["ASI01"])
        with pytest.raises(KeyError, match="No trained policy"):
            ct.best_policy("ASI99")

    def test_train_all(self):
        ct = CategoryTrainer(
            categories=["ASI01", "ASI02"],
            config=PPOConfig(epochs=2, batch_size=4, max_episodes=3),
            action_space=ACTION_SPACE,
        )
        fns = {"ASI01": _simple_scenario_fn, "ASI02": _always_vuln_fn}
        policies = ct.train_all(fns)
        assert "ASI01" in policies
        assert "ASI02" in policies

    def test_train_all_skips_unknown_category(self):
        ct = CategoryTrainer(
            categories=["ASI01"],
            config=PPOConfig(epochs=2, batch_size=4, max_episodes=2),
            action_space=ACTION_SPACE,
        )
        fns = {"ASI01": _simple_scenario_fn, "ASI99": _always_vuln_fn}
        policies = ct.train_all(fns)
        assert "ASI01" in policies
        assert "ASI99" not in policies

    def test_category_trainer_default_action_space(self):
        ct = CategoryTrainer(categories=["ASI01"])
        assert len(ct._action_space) > 0
