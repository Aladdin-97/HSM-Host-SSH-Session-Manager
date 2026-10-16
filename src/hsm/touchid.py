"""Controllo di presenza dell'utente con Touch ID (LocalAuthentication via pyobjc).

Serve a una cosa sola: chiedere "sei davvero tu?" prima di leggere la chiave
del vault dal Keychain. Il risultato è un sì/no, non un segreto.

Limite da tenere a mente: questo è un controllo d'interfaccia, non un
confine di sicurezza. L'item nel Keychain non è legato crittograficamente
alla biometria (servirebbe un binario firmato con entitlement), quindi un
processo malevolo con il tuo utente può saltare questo controllo e leggere
l'item direttamente. Protegge da usi distratti o da chi trova il Mac
sbloccato e lancia `hsm`, non da malware.
"""

import threading
from collections.abc import Callable
from enum import Enum
from typing import Any

# LAPolicyDeviceOwnerAuthentication: Touch ID, con ripiego su Apple Watch o
# sulla password di macOS. Preferita alla variante "solo biometria" perché
# funziona anche a coperchio chiuso o con il sensore temporaneamente bloccato.
POLICY = 2

LA_ERROR_DOMAIN = "com.apple.LocalAuthentication"

# Codici LAError che significano "qui non si può chiedere", non "l'utente
# ha detto no": in questi casi unlock ripiega sulla master password.
_UNAVAILABLE_CODES = frozenset(
    {
        -5,  # LAErrorPasscodeNotSet
        -6,  # LAErrorBiometryNotAvailable
        -7,  # LAErrorBiometryNotEnrolled
        -10,  # LAErrorInvalidContext
        -1004,  # LAErrorNotInteractive (es. sessione SSH, nessuna GUI)
    }
)

# Se il dialog non riceve risposta (utente lontano), lo chiudiamo.
DEFAULT_TIMEOUT_S = 60.0

ContextFactory = Callable[[], Any]


class Presence(Enum):
    """Esito del controllo."""

    GRANTED = "granted"  # l'utente si è autenticato
    DENIED = "denied"  # l'utente ha annullato, ha fallito o non ha risposto
    UNAVAILABLE = "unavailable"  # Touch ID non utilizzabile qui


def _pyobjc_errors() -> tuple[type[Exception], ...]:
    """Le eccezioni con cui pyobjc riporta un errore Objective-C.

    NSInvalidArgumentException diventa ValueError; le altre NSException
    diventano objc.error. Catturiamo solo queste, non Exception in generale.
    """
    try:
        import objc
    except ImportError:
        return (ValueError,)
    return (ValueError, objc.error)


def _default_context() -> Any:
    """Crea un LAContext, o None se pyobjc/LocalAuthentication non c'è."""
    try:
        import LocalAuthentication  # import pigro: solo macOS, solo se serve
    except ImportError:
        return None
    return LocalAuthentication.LAContext.alloc().init()


def require_user_presence(
    reason: str,
    *,
    context_factory: ContextFactory | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> Presence:
    """Mostra il prompt di sistema e attende la risposta dell'utente.

    `reason` compare nel dialog ("python3.12 vuole <reason>"). Non solleva
    eccezioni per i casi previsti: il chiamante decide cosa fare con
    DENIED e UNAVAILABLE. Restituisce GRANTED solo su successo esplicito.
    Un errore di pyobjc vale UNAVAILABLE: unlock ripiega sulla password.
    """
    if not reason:
        raise ValueError("reason non può essere vuoto")
    ctx = (context_factory or _default_context)()
    if ctx is None:
        return Presence.UNAVAILABLE
    try:
        return _evaluate(ctx, reason, timeout)
    except _pyobjc_errors():
        return Presence.UNAVAILABLE
    finally:
        # Chiude un eventuale dialog ancora aperto (timeout) e impedisce di
        # riusare l'autenticazione appena fatta per altre richieste.
        ctx.invalidate()


def _evaluate(ctx: Any, reason: str, timeout: float) -> Presence:
    can, _err = ctx.canEvaluatePolicy_error_(POLICY, None)
    if not can:
        return Presence.UNAVAILABLE

    # evaluatePolicy è asincrono: chiama `reply` su una coda di sistema.
    # Lo trasformiamo in una chiamata bloccante con un Event.
    done = threading.Event()
    # Valori di partenza "chiusi": se la callback si interrompe a metà,
    # quello che resta qui significa DENIED, mai GRANTED.
    outcome: dict[str, Any] = {"success": False, "code": None}

    def reply(success: bool, error: Any) -> None:
        try:
            if error is not None and error.domain() == LA_ERROR_DOMAIN:
                outcome["code"] = error.code()
            # success per ultimo: lo scriviamo solo se tutto il resto è andato.
            outcome["success"] = bool(success)
        finally:
            # Anche se qualcosa sopra solleva, sblocchiamo il thread
            # principale invece di lasciarlo appeso fino al timeout.
            done.set()

    ctx.evaluatePolicy_localizedReason_reply_(POLICY, reason, reply)
    if not done.wait(timeout):
        # Una risposta che arriva dopo il timeout viene ignorata: il dict
        # non viene più letto, e invalidate() chiude comunque il dialog.
        return Presence.DENIED
    if outcome["success"]:
        return Presence.GRANTED
    if outcome["code"] in _UNAVAILABLE_CODES:
        return Presence.UNAVAILABLE
    return Presence.DENIED
