"""Bounded, server-authoritative rules for a two-player 36-card Durak table.

Authentication, table membership, persistence and virtual wallets belong to the
caller. Every accepted action returns a new validated state; rejected or stale
actions never mutate the input. This module has no network or database access.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import random
import re


SUITS = "SHDC"
RANKS = ("6", "7", "8", "9", "10", "J", "Q", "K", "A")
RANK_VALUE = {rank: index for index, rank in enumerate(RANKS)}
CARDS = frozenset(rank + suit for suit in SUITS for rank in RANKS)
SEATS = ("host", "guest")
ACTIONS = frozenset(("ready", "attack", "defend", "take", "pass"))
SCHEMA_VERSION = 2
MAX_HISTORY = 64
MAX_REVISION = 2**53 - 1
_ACTION_ID = re.compile(r"[A-Za-z0-9_-]{8,64}\Z")


class GameError(ValueError):
    """The submitted action or stored state is not valid for this game."""


class StaleStateError(GameError):
    """The caller acted on an older revision and must refresh the table."""


@dataclass(frozen=True)
class ActionResult:
    game: dict
    state: str
    message: str
    changed: bool = True
    started: bool = False
    bout_completed: bool = False
    finished: bool = False


def other(seat: str) -> str:
    if seat not in SEATS:
        raise GameError("Игрок не является участником стола")
    return "guest" if seat == "host" else "host"


def rank(card: str) -> str:
    return card[:-1] if isinstance(card, str) and card in CARDS else ""


def beats(defense: str, attack: str, trump: str) -> bool:
    if any(not isinstance(card, str) or card not in CARDS for card in (defense, attack, trump)):
        return False
    if defense[-1] == attack[-1]:
        return RANK_VALUE[rank(defense)] > RANK_VALUE[rank(attack)]
    return defense[-1] == trump[-1] and attack[-1] != trump[-1]


def _integer(value, minimum: int, maximum: int, message: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise GameError(message)
    return value


def _card_list(value, message: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 36:
        raise GameError(message)
    if any(not isinstance(card, str) or card not in CARDS for card in value):
        raise GameError(message)
    return list(value)


def new_game(rng=None, deck: list[str] | None = None) -> dict:
    """Deal six each, exposing the final card as trump and drawing it last.

    ``deck`` is an optional complete draw-order fixture, not untrusted input.
    In production the OS-backed SystemRandom shuffles the 36-card deck.
    """
    cards = list(deck) if deck is not None else [r + s for s in SUITS for r in RANKS]
    if len(cards) != 36 or set(cards) != CARDS:
        raise GameError("Колода должна содержать 36 разных карт")
    if deck is None:
        (rng or random.SystemRandom()).shuffle(cards)
    trump = cards[-1]
    hands = {seat: [] for seat in SEATS}
    for _ in range(6):
        for seat in SEATS:
            hands[seat].append(cards.pop(0))
    trump_holders = [(RANK_VALUE[rank(card)], seat) for seat in SEATS for card in hands[seat]
                     if card[-1] == trump[-1]]
    attacker = min(trump_holders)[1] if trump_holders else "host"
    return validate_state({
        "schema_version": SCHEMA_VERSION,
        "phase": "ready",
        "ready": {seat: False for seat in SEATS},
        "deck": cards,
        "trump": trump,
        "hands": hands,
        "attacker": attacker,
        "table": [],
        "discard": [],
        "winner": "",
        "bout": 1,
        "bout_limit": min(6, len(hands[other(attacker)])),
        "revision": 0,
        "action_history": [],
    })


def validate_state(value: dict) -> dict:
    """Validate conservation, bounds and turn state, migrating legacy deals.

    The old engine omitted the discard pile. For a legacy state only, absent
    cards are reconstructed as discards; no cards are invented or duplicated.
    Stored finished outcomes are never recalculated (wallets may be settled).
    """
    if not isinstance(value, dict):
        raise GameError("Состояние стола повреждено")
    phase = value.get("phase")
    if phase not in ("ready", "playing", "finished"):
        raise GameError("Раздача ещё не готова")
    schema = value.get("schema_version", 1)
    _integer(schema, 1, SCHEMA_VERSION, "Версия стола не поддерживается")
    ready = value.get("ready")
    if not isinstance(ready, dict) or any(type(ready.get(seat)) is not bool for seat in SEATS):
        raise GameError("Состояние готовности повреждено")
    if phase in ("playing", "finished") and not all(ready[seat] for seat in SEATS):
        raise GameError("Оба игрока должны подтвердить готовность")
    raw_hands = value.get("hands")
    if not isinstance(raw_hands, dict):
        raise GameError("Руки игроков повреждены")
    hands = {seat: _card_list(raw_hands.get(seat), "Руки игроков повреждены") for seat in SEATS}
    deck = _card_list(value.get("deck"), "Колода повреждена")
    trump = value.get("trump")
    if not isinstance(trump, str) or trump not in CARDS:
        raise GameError("Козырь повреждён")
    if trump in deck and deck[-1] != trump:
        raise GameError("Козырь должен быть последней картой колоды")
    attacker = value.get("attacker")
    if attacker not in SEATS:
        raise GameError("Очередь хода повреждена")
    table = value.get("table")
    if not isinstance(table, list) or len(table) > 6:
        raise GameError("Карты стола повреждены")
    pairs = []
    for item in table:
        if not isinstance(item, dict):
            raise GameError("Карты стола повреждены")
        attack, defense = item.get("attack"), item.get("defense", "")
        if not isinstance(attack, str) or attack not in CARDS:
            raise GameError("Карты стола повреждены")
        if not isinstance(defense, str) or (defense and not beats(defense, attack, trump)):
            raise GameError("Карта защиты не бьёт атаку")
        pairs.append({"attack": attack, "defense": defense})
    if phase != "playing" and pairs:
        raise GameError("Карты на столе вне активной раздачи")
    defender_hand_at_start = len(hands[other(attacker)]) + sum(bool(pair["defense"]) for pair in pairs)
    bout_limit = _integer(value.get("bout_limit", min(6, defender_hand_at_start)), 0, 6,
                          "Лимит карт стола повреждён")
    if len(pairs) > bout_limit:
        raise GameError("Превышен лимит атаки")
    inventory = deck + hands["host"] + hands["guest"]
    inventory += [card for item in pairs for card in (item["attack"], item["defense"]) if card]
    if "discard" not in value and schema == 1:
        if len(set(inventory)) != len(inventory):
            raise GameError("В колоде обнаружены дубликаты")
        discard = sorted(CARDS.difference(inventory))
    else:
        discard = _card_list(value.get("discard"), "Отбой повреждён")
    inventory += discard
    if len(inventory) != 36 or set(inventory) != CARDS:
        raise GameError("Нарушена целостность колоды")
    winner = value.get("winner", "")
    if not isinstance(winner, str) or winner not in ("", "host", "guest", "draw"):
        raise GameError("Результат партии повреждён")
    if phase == "finished" and (not winner or deck):
        raise GameError("Результат партии повреждён")
    if phase != "finished" and winner:
        raise GameError("Партия ещё не завершена")
    history = value.get("action_history", [])
    if not isinstance(history, list) or len(history) > MAX_HISTORY:
        raise GameError("История действий повреждена")
    clean_history = []
    revision = _integer(value.get("revision", 0), 0, MAX_REVISION, "Ревизия стола повреждена")
    for entry in history:
        if (not isinstance(entry, dict) or not isinstance(entry.get("id"), str)
                or not _ACTION_ID.fullmatch(entry["id"]) or entry.get("seat") not in SEATS
                or entry.get("action") not in ACTIONS or not isinstance(entry.get("card", ""), str)
                or len(entry.get("card", "")) > 3):
            raise GameError("История действий повреждена")
        target = entry.get("target")
        if target is not None:
            _integer(target, 0, 5, "История действий повреждена")
        clean_history.append({"id": entry["id"], "seat": entry["seat"], "action": entry["action"],
                              "card": entry.get("card", ""), "target": target,
                              "revision": _integer(entry.get("revision"), 1, revision,
                                                   "История действий повреждена")})
    if len({entry["id"] for entry in clean_history}) != len(clean_history):
        raise GameError("История действий повреждена")
    game = {
        "schema_version": SCHEMA_VERSION, "phase": phase,
        "ready": {seat: ready[seat] for seat in SEATS}, "deck": deck, "trump": trump,
        "hands": hands, "attacker": attacker, "table": pairs, "discard": discard,
        "winner": winner,
        "bout": _integer(value.get("bout", 1), 1, MAX_REVISION, "Номер хода повреждён"),
        "bout_limit": bout_limit, "revision": revision, "action_history": clean_history,
    }
    if "stake_q_coins" in value:
        game["stake_q_coins"] = _integer(value["stake_q_coins"], 0, 100_000,
                                          "Ставка стола повреждена")
    if "stake_settled" in value:
        if type(value["stake_settled"]) is not bool:
            raise GameError("Состояние банка повреждено")
        game["stake_settled"] = value["stake_settled"]
    return game


def attack_cards(game: dict, seat: str) -> list[str]:
    if game["phase"] != "playing" or seat != game["attacker"] or len(game["table"]) >= game["bout_limit"]:
        return []
    ranks = {rank(card) for pair in game["table"] for card in (pair["attack"], pair["defense"]) if card}
    return [card for card in game["hands"][seat] if not ranks or rank(card) in ranks]


def defense_options(game: dict, seat: str) -> list[dict]:
    if game["phase"] != "playing" or seat != other(game["attacker"]):
        return []
    return [{"card": card, "target": index} for index, pair in enumerate(game["table"])
            if not pair["defense"] for card in game["hands"][seat]
            if beats(card, pair["attack"], game["trump"])]


def _draw(game: dict, seat: str) -> None:
    while len(game["hands"][seat]) < 6 and game["deck"]:
        game["hands"][seat].append(game["deck"].pop(0))


def _complete_bout(game: dict, taken: bool) -> None:
    attacker, defender = game["attacker"], other(game["attacker"])
    cards = [card for pair in game["table"] for card in (pair["attack"], pair["defense"]) if card]
    if taken:
        game["hands"][defender].extend(cards)
    else:
        game["discard"].extend(cards)
    game["table"] = []
    _draw(game, attacker)
    _draw(game, defender)
    if not game["deck"]:
        empty = [seat for seat in SEATS if not game["hands"][seat]]
        if empty:
            game["phase"] = "finished"
            game["winner"] = "draw" if len(empty) == 2 else empty[0]
            return
    game["attacker"] = attacker if taken else defender
    game["bout"] += 1
    game["bout_limit"] = min(6, len(game["hands"][other(game["attacker"])]))


def apply_action(value: dict, seat: str, action: str, card: str = "", target: int | None = None,
                 expected_revision: int | None = None, action_id: str = "") -> ActionResult:
    """Apply one action, checking a revision and deduplicating optional IDs.

    The caller must serialize persistence (e.g. BEGIN IMMEDIATE). A duplicate
    action ID with the identical payload returns the current state without
    replaying cards or charging/paying a virtual stake a second time. A missing
    target selects the first *beatable* uncovered pair for older APKs.
    """
    other(seat)
    if not isinstance(action, str) or action not in ACTIONS:
        raise GameError("Неизвестное действие игры")
    if not isinstance(card, str) or len(card) > 3:
        raise GameError("Эта карта недоступна")
    if target is not None:
        _integer(target, 0, 5, "Неверная карта для защиты")
    if expected_revision is not None:
        _integer(expected_revision, 0, MAX_REVISION, "Неверная ревизия стола")
    if not isinstance(action_id, str) or (action_id and not _ACTION_ID.fullmatch(action_id)):
        raise GameError("Неверный идентификатор действия")
    game = validate_state(value)
    if action_id:
        previous = next((entry for entry in game["action_history"] if entry["id"] == action_id), None)
        if previous:
            if any(previous[key] != expected for key, expected in
                   (("seat", seat), ("action", action), ("card", card), ("target", target))):
                raise GameError("Идентификатор действия уже использован")
            return ActionResult(game, game["phase"], "Действие уже обработано", changed=False,
                                finished=game["phase"] == "finished")
    if expected_revision is not None and expected_revision != game["revision"]:
        raise StaleStateError("Стол обновился. Обновите карты и повторите действие")
    started = completed = False
    if action == "ready":
        if card or target is not None:
            raise GameError("Готовность не содержит карту")
        if game["ready"][seat]:
            return ActionResult(game, game["phase"], "Готовность уже подтверждена", changed=False,
                                finished=game["phase"] == "finished")
        if game["phase"] != "ready":
            raise GameError("Раздача уже началась")
        game["ready"][seat] = True
        if all(game["ready"].values()):
            game["phase"] = "playing"
            started = True
            message = "Раздача началась"
        else:
            message = "Готовность подтверждена. Ожидаем второго игрока"
    else:
        if game["phase"] != "playing":
            raise GameError("Сначала оба игрока должны подтвердить готовность")
        attacker, defender = game["attacker"], other(game["attacker"])
        if action == "attack":
            if target is not None or card not in attack_cards(game, seat):
                raise GameError("Эту карту сейчас нельзя подкинуть")
            game["hands"][seat].remove(card)
            game["table"].append({"attack": card, "defense": ""})
            message = "Атака"
        elif action == "defend":
            options = defense_options(game, seat)
            if target is None:
                selected = next((option for option in options if option["card"] == card), None)
                if selected is None:
                    raise GameError("Эта карта не бьёт ни одну открытую атаку")
                selected_target = selected["target"]
            else:
                if {"card": card, "target": target} not in options:
                    raise GameError("Эта карта не бьёт выбранную атаку")
                selected_target = target
            game["hands"][seat].remove(card)
            game["table"][selected_target]["defense"] = card
            message = "Карта отбита"
        elif action == "take":
            if card or target is not None or seat != defender or not game["table"]:
                raise GameError("Взять карты может только защищающийся")
            _complete_bout(game, taken=True)
            completed = True
            message = "Защищающийся взял карты. Атакующий ходит снова"
        elif action == "pass":
            if (card or target is not None or seat != attacker or not game["table"]
                    or not all(pair["defense"] for pair in game["table"])):
                raise GameError("В отбой можно отправить только полностью отбитые карты")
            _complete_bout(game, taken=False)
            completed = True
            message = "Карты ушли в отбой. Ход передан"
    game["revision"] += 1
    if action_id:
        game["action_history"].append({"id": action_id, "seat": seat, "action": action,
                                       "card": card, "target": target, "revision": game["revision"]})
        game["action_history"] = game["action_history"][-MAX_HISTORY:]
    if game["phase"] == "finished":
        message = "Партия завершена вничью" if game["winner"] == "draw" else "Партия завершена"
    game = validate_state(game)
    return ActionResult(game, game["phase"], message, started=started, bout_completed=completed,
                        finished=game["phase"] == "finished")


def public_view(value: dict | None, seat: str) -> dict:
    """Serialize only one player's hand and bounded legal UI options."""
    other(seat)
    inactive = {
        "game_phase": "waiting", "hand": [], "opponent_cards": 0, "table_cards": [],
        "trump": "", "deck_count": 0, "discard_count": 0, "attacker": "", "winner": "",
        "revision": 0, "bout": 0, "bout_limit": 0,
        "can_ready": False, "can_attack": False, "can_defend": False,
        "can_take": False, "can_pass": False, "legal_attack_cards": [], "legal_defenses": [],
        "message": "Ожидаем второго игрока…",
    }
    if not value:
        return inactive
    try:
        game = validate_state(value)
    except GameError:
        return {**inactive, "game_phase": "unavailable",
                "message": "Не удалось восстановить раздачу. Обратитесь в поддержку: оператор проверит стол и виртуальный банк"}
    phase = game["phase"]
    attacks = attack_cards(game, seat)
    defenses = defense_options(game, seat)
    playing = phase == "playing"
    table = deepcopy(game["table"])
    all_defended = bool(table) and all(pair["defense"] for pair in table)
    if phase == "ready":
        message = ("Ожидаем подтверждения второго игрока" if game["ready"][seat]
                   else "Игрок подключился. Подтвердите готовность к раздаче")
    elif phase == "finished":
        message = "Ничья" if game["winner"] == "draw" else ("Вы выиграли" if game["winner"] == seat else "Партия завершена")
    elif seat == game["attacker"]:
        message = "Можно отправить карты в отбой или подкинуть" if all_defended else "Ваш ход: выберите карту для атаки"
    else:
        message = "Отбейте карты или нажмите «Беру»" if table else "Ожидаем хода соперника"
    return {
        "game_phase": phase, "hand": list(game["hands"][seat]) if phase != "ready" else [],
        "opponent_cards": len(game["hands"][other(seat)]), "table_cards": table,
        "trump": game["trump"], "deck_count": len(game["deck"]),
        "discard_count": len(game["discard"]), "attacker": game["attacker"], "winner": game["winner"],
        "revision": game["revision"], "bout": game["bout"], "bout_limit": game["bout_limit"],
        "can_ready": phase == "ready" and not game["ready"][seat],
        "can_attack": bool(attacks), "can_defend": bool(defenses),
        "can_take": playing and seat == other(game["attacker"]) and bool(table),
        "can_pass": playing and seat == game["attacker"] and all_defended,
        "legal_attack_cards": attacks, "legal_defenses": defenses, "message": message,
    }
