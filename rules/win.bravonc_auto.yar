rule win_bravonc_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.bravonc."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bravonc"
        malpedia_rule_date = "20220405"
        malpedia_hash = "ecd38294bd47d5589be5cd5490dc8bb4804afc2a"
        malpedia_version = ""
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 740d 56 8b7118 037114 c1e604 8932 5e }
            // n = 7, score = 100
            //   740d                 | je                  0xf
            //   56                   | push                esi
            //   8b7118               | mov                 esi, dword ptr [ecx + 0x18]
            //   037114               | add                 esi, dword ptr [ecx + 0x14]
            //   c1e604               | shl                 esi, 4
            //   8932                 | mov                 dword ptr [edx], esi
            //   5e                   | pop                 esi

        $sequence_1 = { 8d4dc8 5f 57 685a230000 }
            // n = 4, score = 100
            //   8d4dc8               | lea                 ecx, dword ptr [ebp - 0x38]
            //   5f                   | pop                 edi
            //   57                   | push                edi
            //   685a230000           | push                0x235a

        $sequence_2 = { 8d84019979825a 8945f0 e8???????? 8945ec 8b86c0000000 6a18 ff703c }
            // n = 7, score = 100
            //   8d84019979825a       | lea                 eax, dword ptr [ecx + eax + 0x5a827999]
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   e8????????           |                     
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8b86c0000000         | mov                 eax, dword ptr [esi + 0xc0]
            //   6a18                 | push                0x18
            //   ff703c               | push                dword ptr [eax + 0x3c]

        $sequence_3 = { 5b 740b 57 8bce ff7508 e8???????? 8bc7 }
            // n = 7, score = 100
            //   5b                   | pop                 ebx
            //   740b                 | je                  0xd
            //   57                   | push                edi
            //   8bce                 | mov                 ecx, esi
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   8bc7                 | mov                 eax, edi

        $sequence_4 = { c1e818 33c7 5f c1ee08 8b04853cc64000 33c6 5e }
            // n = 7, score = 100
            //   c1e818               | shr                 eax, 0x18
            //   33c7                 | xor                 eax, edi
            //   5f                   | pop                 edi
            //   c1ee08               | shr                 esi, 8
            //   8b04853cc64000       | mov                 eax, dword ptr [eax*4 + 0x40c63c]
            //   33c6                 | xor                 eax, esi
            //   5e                   | pop                 esi

        $sequence_5 = { c74620be6a4000 897e28 397e24 7507 }
            // n = 4, score = 100
            //   c74620be6a4000       | mov                 dword ptr [esi + 0x20], 0x406abe
            //   897e28               | mov                 dword ptr [esi + 0x28], edi
            //   397e24               | cmp                 dword ptr [esi + 0x24], edi
            //   7507                 | jne                 9

        $sequence_6 = { ff15???????? 59 8bf0 ff15???????? 03f0 ff15???????? 03f0 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   59                   | pop                 ecx
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     
            //   03f0                 | add                 esi, eax
            //   ff15????????         |                     
            //   03f0                 | add                 esi, eax

        $sequence_7 = { 57 ffd3 59 85c0 59 750e }
            // n = 6, score = 100
            //   57                   | push                edi
            //   ffd3                 | call                ebx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   59                   | pop                 ecx
            //   750e                 | jne                 0x10

        $sequence_8 = { c1e104 3bc1 0f8296010000 8d4de0 e8???????? 8b0e 030f }
            // n = 7, score = 100
            //   c1e104               | shl                 ecx, 4
            //   3bc1                 | cmp                 eax, ecx
            //   0f8296010000         | jb                  0x19c
            //   8d4de0               | lea                 ecx, dword ptr [ebp - 0x20]
            //   e8????????           |                     
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   030f                 | add                 ecx, dword ptr [edi]

        $sequence_9 = { 8d4dc8 c645fc01 8845c8 ff15???????? 8065ef00 8d85a4feffff 50 }
            // n = 7, score = 100
            //   8d4dc8               | lea                 ecx, dword ptr [ebp - 0x38]
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   8845c8               | mov                 byte ptr [ebp - 0x38], al
            //   ff15????????         |                     
            //   8065ef00             | and                 byte ptr [ebp - 0x11], 0
            //   8d85a4feffff         | lea                 eax, dword ptr [ebp - 0x15c]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 131072
}