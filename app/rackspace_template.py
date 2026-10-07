RACKSPACE_MAILBOX_HEADERS = [
    "Username",
    "Password",
    "Enabled",
    "First Name",
    "Middle Initial",
    "Last Name",
    "Alternate Email",
    "Organization",
    "Department",
    "Title",
    "Mobile Phone Number",
    "Business Phone Number",
    "Street",
    "City",
    "State",
    "Postal Code",
    "Country",
    "Notes",
    "UserID",
    "CustomID",
    "VisibleInCompanyDirectory",
    "VisibleInGAL",
]


def rackspace_row(user: dict, password: str) -> list[str]:
    # Rackspace import is scoped to the selected domain, so Username must be
    # the mailbox local-part only (e.g. nigel.brown), not the full email.
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
