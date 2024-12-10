rule DiscordTokenStealer : malware {
    meta:
        name        = "DiscordTokenStealer"
        category    = "stealer"
        description = "Discord token stealer rule"
        author      = "remiliacn"
        created     = "2024-12-08"
        reliability = 90

    strings:
        $token = "dQw4w9WgXcQ"
        $discord_db = "\\discord\\Local Storage\\leveldb\\"
        $discord_canary_db = "\\discordcanary\\Local Storage\\leveldb\\"
        $discord_ptb_db = "\\discordptb\\Local Storage\\leveldb\\"

    condition:
        $token and ($discord_db or $discord_canary_db or $discord_ptb_db)
}

rule PysilonStealerMatcher : malware {
    meta:
        name        = "PysilonStealerMatcher"
        category    = "stealer"
        description = "Pysilon Stealer Rule Match"
        author      = "remiliacn"
        created     = "2024-12-08"
        reliability = 90

    strings:
        $ = ".pysilon"
		$ = "\\PySilon.key"

    condition:
        any of them
}

rule DiscordTokenValidation : suspicious {
    meta:
        name        = "DiscordTokenValidation"
        category    = "stealer"
        description = "Post request sent to usually verify discord token"
        author      = "remiliacn"
        created     = "2024-12-09"
        reliability = 70

	strings:
		$ = /api\/v\d+\/users\/@me/

    condition:
        any of them
}

rule RayxStealer : malware {
    meta:
        name        = "RayxStealer"
        category    = "library"
        description = "Suspicious use of notoken library"
        author      = "remiliacn"
        created     = "2024-12-09"
        reliability = 80

    strings:
        $ = /notoken\d+\.\w+/i

    condition:
        any of them
}
