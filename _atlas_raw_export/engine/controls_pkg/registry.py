from engine.controls.identity.risky_signin_mfa import CONTROL as RISKY_SIGNIN_MFA
from engine.controls.identity.risky_user_password import CONTROL as RISKY_USER_PASSWORD
from engine.controls.identity.admin_mfa import CONTROL as ADMIN_MFA

CONTROL_REGISTRY = {
    RISKY_SIGNIN_MFA["id"]: RISKY_SIGNIN_MFA,
    RISKY_USER_PASSWORD["id"]: RISKY_USER_PASSWORD,
    ADMIN_MFA["id"]: ADMIN_MFA,
}