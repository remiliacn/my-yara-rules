rule UsesDiscordWebhook : suspicious {
    meta:
        name        = "UsesDiscordWebhook"
        category    = "network"
        description = "This rule captures discord webhook urls"
        author      = "remiliacn"
        created     = "2024-12-09"
        reliability = 90

    strings:
		/* Discord webhook looks like: https://discord.com/api/webhooks/{number}/{token} */
        $webhook = /https?:\/\/*discord\.com\/api\/webhooks\/\d+\/.{68}/ ascii wide

    condition:
        $webhook
}

rule DiscordPyFramework : tool {
    meta:
        name        = "DiscordPyFramework"
        category    = "library"
        description = "This rule matches executable that uses discord.py"
        author      = "remiliacn"
        created     = "2024-12-09"
        reliability = 80
		tlp         = "TLP:white"

    strings:
        $ = "discord.ext"

    condition:
        any of them
}
