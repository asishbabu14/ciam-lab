"""Run the storefront. In local mode, also run both mock identity providers."""

from __future__ import annotations

import time

from ciam_lab.config import settings_from_env
from ciam_lab.runtime import start_lab


def main() -> None:
    settings = settings_from_env()
    lab = start_lab(settings)
    mode = "MOCK:local-idp" if settings.local_mode else "auth0"
    print(f"storefront  {settings.app_base}  ({mode})")
    if settings.local_mode:
        print(f"customer    {settings.customer_issuer}  MOCK:local-idp")
        print(f"enterprise  {settings.enterprise_issuer}  MOCK:enterprise-idp")
        print("synthetic sign-in: alice@example.com / correct-horse")
    else:
        print("Auth0 mode. Passkeys and the local enterprise broker stay in local mode.")
    print("ctrl-c stops the lab")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        from ciam_lab.runtime import stop_lab

        stop_lab(lab)


if __name__ == "__main__":
    main()
