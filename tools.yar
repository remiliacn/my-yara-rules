rule PyArmor : tool {
    meta:
        name        = "PyArmor"
        category    = "packer"
        description = "Python Armor is usually used to obfuscate malware payload"
        author      = "remiliacn"
        created     = "2024-12-11"
        reliability = 85
        tlp         = "TLP:amber"

    strings:
        $ = "__pyarmor__"

    condition:
        any of them
}
