RACKSPACE_MAILBOX_HEADERS = [
    "Username",
    "Password",
    "Enabled",
    "FirstName",
    "MiddleInitial",
    "LastName",
    "AlternateEmail",
    "Organization",
    "Department",
    "Title",
    "MobilePhoneNumber",
    "BusinessPhoneNumber",
    "Street",
    "City",
    "State",
    "PostalCode",
    "Country",
    "Notes",
    "UserID",
    "CustomID",
    "VisibleInCompanyDirectory",
    "VisibleInGAL",
]


def rackspace_row(user: dict, password: str) -> list[str]:
    # Rackspace import is already scoped to the selected domain, therefore
    # Username is the mailbox local-part only (e.g. nigel.brown).
    source_email = (user.get("source_email") or "").strip()
    username = source_email.split("@", 1)[0] if "@" in source_email else source_email

    return [
        username,
        password,
        "1",
        user.get("first_name") or "",
        "",
        user.get("last_name") or "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "1",
        "1",
    ]
