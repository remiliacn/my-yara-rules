rule MbrDeletion : malware {
    meta:
        name        = "MbrDeletion"
        category    = "destruction"
        description = "This rule is to detect mbr manipulation"
        author      = "remiliacn"
        created     = "2024-12-09"
        reliability = 60

    strings:
        $select = /select disk \d+/s 
		$clean = "clean"

    condition:
        $select and $clean
}

rule Taskkill : suspicious {
    meta:
        name        = "Taskkill"
        category    = "tampering"
        description = "Detects taskkill operations on Windows platform"
        author      = "remiliacn"
        created     = "2024-12-09"
        reliability = 90

    strings:
        $ = /taskkill\s.*?\/f.*?\.exe/s 
		$ = /taskkill\s.*?\/im.*?\.exe/s 

    condition:
        any of them
}
