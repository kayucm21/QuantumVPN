"""Offline regression and conservation tests for the authoritative card engine."""

from copy import deepcopy
import random
import unittest

try:
    from . import quantumvpn_durak as durak
except ImportError:
    import quantumvpn_durak as durak


def fixture(host, guest, *, deck=None, table=None, trump="AS", attacker="host", phase="playing",
            bout_limit=None, discard=None):
    deck = list(deck or [])
    table = list(table or [])
    used = host + guest + deck + [card for pair in table for card in pair.values() if card]
    return durak.validate_state({
        "schema_version": 2, "phase": phase, "hands": {"host": host, "guest": guest},
        "deck": deck, "table": table, "trump": trump, "attacker": attacker,
        "ready": {"host": phase != "ready", "guest": phase != "ready"},
        "winner": "", "revision": 0, "bout": 1,
        "bout_limit": min(6, len(guest if attacker == "host" else host)) if bout_limit is None else bout_limit,
        "discard": sorted(durak.CARDS.difference(used)) if discard is None else discard,
    })


def inventory(game):
    return (game["deck"] + game["hands"]["host"] + game["hands"]["guest"] + game["discard"]
            + [card for pair in game["table"] for card in pair.values() if card])


class DurakRulesTests(unittest.TestCase):
    def assertConserved(self, game):
        self.assertEqual(len(inventory(game)), 36)
        self.assertEqual(set(inventory(game)), durak.CARDS)
        durak.validate_state(game)

    def assertRejectedUnchanged(self, game, *args, **kwargs):
        before = deepcopy(game)
        with self.assertRaises(durak.GameError):
            durak.apply_action(game, *args, **kwargs)
        self.assertEqual(game, before)

    def test_deals_six_and_trump_is_last_card(self):
        game = durak.new_game(rng=random.Random(19))
        self.assertEqual([len(game["hands"][seat]) for seat in durak.SEATS], [6, 6])
        self.assertEqual(len(game["deck"]), 24)
        self.assertEqual(game["deck"][-1], game["trump"])
        self.assertConserved(game)

    def test_lowest_initial_trump_attacks(self):
        first = ["7S", "6S", "6H", "7H", "6D", "7D", "6C", "7C", "8H", "8D", "8C", "9H"]
        rest = sorted(durak.CARDS.difference(first + ["AS"])) + ["AS"]
        game = durak.new_game(deck=first + rest)
        self.assertEqual(game["attacker"], "guest")

    def test_waiting_ready_have_no_play_actions_or_hand(self):
        for seat in durak.SEATS:
            waiting = durak.public_view(None, seat)
            self.assertFalse(any(waiting[key] for key in ("can_ready", "can_attack", "can_defend", "can_take", "can_pass")))
            ready = durak.public_view(durak.new_game(rng=random.Random(3)), seat)
            self.assertTrue(ready["can_ready"])
            self.assertEqual(ready["hand"], [])
            self.assertFalse(any(ready[key] for key in ("can_attack", "can_defend", "can_take", "can_pass")))

    def test_both_must_be_ready_and_retries_do_not_start_twice(self):
        game = durak.new_game(rng=random.Random(2))
        self.assertRejectedUnchanged(game, "host", "attack", game["hands"]["host"][0])
        first = durak.apply_action(game, "host", "ready", expected_revision=0, action_id="readyhost01")
        self.assertFalse(first.started)
        self.assertEqual(first.game["phase"], "ready")
        again = durak.apply_action(first.game, "host", "ready")
        self.assertFalse(again.changed)
        started = durak.apply_action(first.game, "guest", "ready", expected_revision=1, action_id="readyguest01")
        self.assertTrue(started.started)
        self.assertEqual(started.game["phase"], "playing")
        duplicate = durak.apply_action(started.game, "guest", "ready", expected_revision=1, action_id="readyguest01")
        self.assertFalse(duplicate.started)
        self.assertFalse(duplicate.changed)
        self.assertEqual(duplicate.game["revision"], 2)

    def test_beating_rules_same_suit_and_trump(self):
        self.assertTrue(durak.beats("7H", "6H", "AS"))
        self.assertFalse(durak.beats("6H", "7H", "AS"))
        self.assertFalse(durak.beats("7D", "6H", "AS"))
        self.assertTrue(durak.beats("6S", "AH", "AS"))
        self.assertFalse(durak.beats("AH", "6S", "AS"))
        self.assertFalse(durak.beats("6S", "7S", "AS"))
        self.assertFalse(durak.beats("7S", "7S", "AS"))
        self.assertFalse(durak.beats([], "6H", "AS"))

    def test_defend_and_take_do_not_raise_unpack_error(self):
        game = fixture(["6H", "8C"], ["7H", "9D"], deck=["AS"])
        attacked = durak.apply_action(game, "host", "attack", "6H")
        defended = durak.apply_action(attacked.game, "guest", "defend", "7H")
        self.assertEqual(defended.game["table"], [{"attack": "6H", "defense": "7H"}])
        taken = durak.apply_action(defended.game, "guest", "take")
        self.assertTrue(taken.bout_completed)
        self.assertTrue({"6H", "7H"}.issubset(taken.game["hands"]["guest"]))
        self.assertEqual(taken.game["attacker"], "host")
        self.assertConserved(taken.game)

    def test_defend_specific_pair_and_legacy_auto_select_beatable(self):
        game = fixture(["8C"], ["7S", "8H"], table=[{"attack": "6H", "defense": ""},
                                                   {"attack": "6S", "defense": ""}],
                       trump="AC", bout_limit=2)
        defended = durak.apply_action(game, "guest", "defend", "7S", target=1).game
        self.assertEqual(defended["table"][0]["defense"], "")
        self.assertEqual(defended["table"][1]["defense"], "7S")
        old_apk = durak.apply_action(game, "guest", "defend", "7S").game
        self.assertEqual(old_apk["table"], defended["table"])
        self.assertRejectedUnchanged(game, "guest", "defend", "7S", target=0)

    def test_bout_limit_is_frozen_when_defender_plays_cards(self):
        game = fixture(["6H", "6D", "6C", "6S"], ["7H", "7D", "7C"], deck=["AS"])
        for attack, defense in (("6H", "7H"), ("6D", "7D"), ("6C", "7C")):
            game = durak.apply_action(game, "host", "attack", attack).game
            game = durak.apply_action(game, "guest", "defend", defense).game
        self.assertEqual(len(game["table"]), 3)
        self.assertEqual(game["bout_limit"], 3)
        self.assertEqual(game["hands"]["guest"], [])
        self.assertRejectedUnchanged(game, "host", "attack", "6S")
        self.assertTrue(durak.public_view(game, "host")["can_pass"])
        self.assertConserved(game)

    def test_limit_is_never_more_than_six(self):
        attacks = [rank + "H" for rank in durak.RANKS[:7]]
        defenses = [rank + "S" for rank in durak.RANKS[:7]]
        game = fixture(attacks, defenses, trump="AS")
        game["bout_limit"] = 6
        for index in range(6):
            if index:
                # Attack ranks must match the table. A trump defense supplies
                # the following rank for the next legal non-trump attack.
                previous = game["table"][-1]["defense"]
                self.assertEqual(durak.rank(attacks[index]), durak.rank(previous))
            game = durak.apply_action(game, "host", "attack", attacks[index]).game
            game = durak.apply_action(game, "guest", "defend", defenses[index + 1]).game
        self.assertEqual(len(game["table"]), 6)
        self.assertRejectedUnchanged(game, "host", "attack", attacks[6])

    def test_bad_rank_wrong_seat_and_cards_not_owned_rejected(self):
        game = fixture(["6H", "8H", "6D"], ["7H", "9D"], deck=["AS"])
        game = durak.apply_action(game, "host", "attack", "6H").game
        self.assertRejectedUnchanged(game, "host", "attack", "8H")
        self.assertRejectedUnchanged(game, "guest", "attack", "9D")
        self.assertRejectedUnchanged(game, "host", "defend", "6D")
        self.assertRejectedUnchanged(game, "guest", "defend", "7D")
        self.assertRejectedUnchanged(game, "host", "take")
        self.assertRejectedUnchanged(game, "host", "pass")

    def test_end_round_moves_all_cards_to_discard_and_draws_to_six(self):
        game = fixture(["6H", "8C", "9C", "JC", "QC", "KC"],
                       ["7H", "8D", "9D", "JD", "QD", "KD"], deck=["10C", "10D", "AS"])
        game = durak.apply_action(game, "host", "attack", "6H").game
        game = durak.apply_action(game, "guest", "defend", "7H").game
        discard_before = len(game["discard"])
        result = durak.apply_action(game, "host", "pass")
        self.assertTrue(result.bout_completed)
        self.assertEqual(len(result.game["discard"]), discard_before + 2)
        self.assertEqual(result.game["table"], [])
        self.assertEqual([len(result.game["hands"][seat]) for seat in durak.SEATS], [6, 6])
        self.assertIn("10C", result.game["hands"]["host"])
        self.assertIn("10D", result.game["hands"]["guest"])
        self.assertEqual(result.game["deck"], ["AS"])
        self.assertEqual(result.game["attacker"], "guest")
        self.assertConserved(result.game)

    def test_only_three_missing_cards_drawn_and_attacker_draws_first(self):
        game = fixture(["6H", "8C", "9C", "10H"], ["7H", "8D", "9D", "JD", "QD", "KD"],
                       deck=["10C", "JC", "QC", "KC", "AS"])
        game = durak.apply_action(game, "host", "attack", "6H").game
        game = durak.apply_action(game, "guest", "defend", "7H").game
        result = durak.apply_action(game, "host", "pass")
        self.assertEqual(result.game["hands"]["host"], ["8C", "9C", "10H", "10C", "JC", "QC"])
        self.assertEqual(result.game["hands"]["guest"][-1], "KC")
        self.assertEqual(len(result.game["hands"]["guest"]), 6)
        self.assertEqual(result.game["deck"], ["AS"])
        self.assertConserved(result.game)

    def test_last_trump_drawn_even_if_defender_cannot_refill(self):
        game = fixture(["6H", "8C", "9C", "JC", "QC", "KC"], ["7H", "9D"], deck=["AS"])
        game = durak.apply_action(game, "host", "attack", "6H").game
        game = durak.apply_action(game, "guest", "defend", "7H").game
        result = durak.apply_action(game, "host", "pass")
        self.assertEqual(result.game["hands"]["host"][-1], "AS")
        self.assertEqual(result.game["hands"]["guest"], ["9D"])
        self.assertConserved(result.game)

    def test_take_includes_defended_pairs_and_does_not_draw_over_six(self):
        game = fixture(["6H", "6D", "8C", "9C", "JC", "QC"],
                       ["7H", "8D", "9D", "JD", "QD", "KD"], deck=["10C", "KC", "AS"])
        game = durak.apply_action(game, "host", "attack", "6H").game
        game = durak.apply_action(game, "guest", "defend", "7H").game
        game = durak.apply_action(game, "host", "attack", "6D").game
        result = durak.apply_action(game, "guest", "take")
        self.assertEqual(len(result.game["hands"]["guest"]), 8)
        self.assertTrue({"6H", "7H", "6D"}.issubset(result.game["hands"]["guest"]))
        self.assertEqual(result.game["hands"]["host"][-2:], ["10C", "KC"])
        self.assertEqual(result.game["deck"], ["AS"])
        self.assertEqual(result.game["attacker"], "host")
        self.assertConserved(result.game)

    def test_attacking_last_card_never_settles_before_defense_or_take(self):
        game = fixture(["6H"], ["7H", "9D"])
        attacked = durak.apply_action(game, "host", "attack", "6H")
        self.assertFalse(attacked.finished)
        self.assertEqual(attacked.game["winner"], "")
        defended = durak.apply_action(attacked.game, "guest", "defend", "7H")
        self.assertFalse(defended.finished)
        finished = durak.apply_action(defended.game, "host", "pass")
        self.assertTrue(finished.finished)
        self.assertEqual(finished.game["winner"], "host")
        self.assertConserved(finished.game)

    def test_empty_attacker_wins_after_defender_takes(self):
        game = fixture(["6H"], ["9D"])
        game = durak.apply_action(game, "host", "attack", "6H").game
        result = durak.apply_action(game, "guest", "take")
        self.assertEqual(result.game["winner"], "host")
        self.assertEqual(result.game["hands"]["guest"], ["9D", "6H"])

    def test_empty_defender_wins_after_successful_completed_bout(self):
        game = fixture(["6H", "9D"], ["7H"])
        game = durak.apply_action(game, "host", "attack", "6H").game
        game = durak.apply_action(game, "guest", "defend", "7H").game
        self.assertEqual(game["phase"], "playing")
        result = durak.apply_action(game, "host", "pass")
        self.assertEqual(result.game["winner"], "guest")

    def test_both_empty_is_draw_not_reversed_winner(self):
        game = fixture(["6H"], ["7H"])
        game = durak.apply_action(game, "host", "attack", "6H").game
        game = durak.apply_action(game, "guest", "defend", "7H").game
        result = durak.apply_action(game, "host", "pass")
        self.assertEqual(result.game["winner"], "draw")
        self.assertEqual(len(result.game["discard"]), 36)
        self.assertConserved(result.game)

    def test_idempotency_and_revision_conflicts_are_non_mutating(self):
        game = fixture(["6H", "9D"], ["7H", "8D"], deck=["AS"])
        attacked = durak.apply_action(game, "host", "attack", "6H", expected_revision=0, action_id="attackfirst01")
        duplicate = durak.apply_action(attacked.game, "host", "attack", "6H", expected_revision=0, action_id="attackfirst01")
        self.assertFalse(duplicate.changed)
        self.assertEqual(duplicate.game, attacked.game)
        self.assertRejectedUnchanged(attacked.game, "host", "attack", "9D", action_id="attackfirst01")
        self.assertRejectedUnchanged(attacked.game, "guest", "defend", "7H", expected_revision=0)
        self.assertRejectedUnchanged(attacked.game, "guest", "defend", "7H", action_id="x")

    def test_untrusted_action_types_and_targets_fail_closed(self):
        game = fixture(["6H", "9D"], ["7H", "8D"], deck=["AS"])
        for action in ([], {}, 5, None):
            self.assertRejectedUnchanged(game, "host", action)
        for target in (-1, 6, True, "0", []):
            self.assertRejectedUnchanged(game, "guest", "defend", "7H", target=target)
        self.assertRejectedUnchanged(game, "host", "attack", "6H", expected_revision=True)
        self.assertRejectedUnchanged(game, "host", "attack", "6H", action_id=[])

    def test_legacy_discard_migration_keeps_wallet_and_outcome(self):
        game = fixture(["6H", "8C"], ["9D"], table=[{"attack": "6D", "defense": "7D"}],
                       bout_limit=2)
        game.pop("schema_version")
        game.pop("discard")
        game.pop("bout_limit")
        game["stake_q_coins"] = 40
        game["stake_settled"] = False
        migrated = durak.validate_state(game)
        self.assertEqual(migrated["bout_limit"], 2)
        self.assertEqual(migrated["stake_q_coins"], 40)
        self.assertFalse(migrated["stake_settled"])
        self.assertConserved(migrated)
        ended = fixture([], ["9D"])
        ended.update({"phase": "finished", "winner": "guest", "stake_q_coins": 40, "stake_settled": True})
        ended.pop("schema_version")
        ended.pop("discard")
        # Legacy outcomes may be wrong, but re-reading a settled game cannot
        # retrospectively move anybody's virtual balance.
        self.assertEqual(durak.validate_state(ended)["winner"], "guest")

    def test_invalid_inventory_and_oversized_state_fail_closed(self):
        game = fixture(["6H"], ["7H"])
        for bad in (
            {**game, "deck": ["6H"]},
            {**game, "discard": game["discard"][:-1]},
            {**game, "table": [{"attack": "9C", "defense": ""}] * 7},
            {**game, "revision": True},
            {**game, "ready": {"host": "yes", "guest": True}},
        ):
            with self.assertRaises(durak.GameError):
                durak.validate_state(bad)
            view = durak.public_view(bad, "host")
            self.assertEqual(view["game_phase"], "unavailable")
            self.assertFalse(view["can_take"])
            self.assertEqual(view["hand"], [])

    def test_public_view_never_exposes_opponent_hand_deck_or_history(self):
        game = fixture(["6H", "9D"], ["7H", "8D"], deck=["AS"])
        game = durak.apply_action(game, "host", "attack", "6H", action_id="attackfirst01").game
        view = durak.public_view(game, "guest")
        self.assertEqual(view["hand"], ["7H", "8D"])
        self.assertEqual(view["opponent_cards"], 1)
        self.assertEqual(view["legal_defenses"], [{"card": "7H", "target": 0}])
        self.assertTrue(view["can_take"])
        self.assertFalse(view["can_pass"])
        self.assertNotIn("deck", view)
        self.assertNotIn("hands", view)
        self.assertNotIn("action_history", view)

    def test_randomized_complete_games_conserve_every_card(self):
        for seed in range(80):
            with self.subTest(seed=seed):
                rng = random.Random(seed)
                game = durak.new_game(rng=rng)
                for seat in durak.SEATS:
                    game = durak.apply_action(game, seat, "ready").game
                for sequence in range(4000):
                    self.assertConserved(game)
                    if game["phase"] == "finished":
                        break
                    attacker, defender = game["attacker"], durak.other(game["attacker"])
                    attack_view, defense_view = durak.public_view(game, attacker), durak.public_view(game, defender)
                    if not game["table"]:
                        self.assertTrue(attack_view["can_attack"])
                        action = (attacker, "attack", rng.choice(attack_view["legal_attack_cards"]), None)
                    elif any(not pair["defense"] for pair in game["table"]):
                        if defense_view["legal_defenses"]:
                            option = rng.choice(defense_view["legal_defenses"])
                            action = (defender, "defend", option["card"], option["target"])
                        else:
                            action = (defender, "take", "", None)
                    elif attack_view["legal_attack_cards"] and rng.random() < 0.7:
                        action = (attacker, "attack", rng.choice(attack_view["legal_attack_cards"]), None)
                    else:
                        action = (attacker, "pass", "", None)
                    before = deepcopy(game)
                    result = durak.apply_action(game, *action, expected_revision=game["revision"],
                                                action_id=f"seed{seed}action{sequence}")
                    self.assertEqual(game, before)
                    self.assertEqual(result.game["revision"], before["revision"] + 1)
                    game = result.game
                    self.assertLessEqual(len(game["action_history"]), durak.MAX_HISTORY)
                else:
                    self.fail("Random game did not finish within the bounded action budget")
                self.assertEqual(game["table"], [])
                self.assertEqual(game["deck"], [])
                self.assertTrue(any(not game["hands"][seat] for seat in durak.SEATS))
                self.assertConserved(game)


if __name__ == "__main__":
    unittest.main()
