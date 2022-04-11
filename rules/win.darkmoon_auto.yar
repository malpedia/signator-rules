rule win_darkmoon_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.darkmoon."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkmoon"
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
        $sequence_0 = { 0bc0 7506 5f e9???????? c745f400000000 57 }
            // n = 6, score = 100
            //   0bc0                 | or                  eax, eax
            //   7506                 | jne                 8
            //   5f                   | pop                 edi
            //   e9????????           |                     
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   57                   | push                edi

        $sequence_1 = { 8bda f7eb c1fa02 8bc2 }
            // n = 4, score = 100
            //   8bda                 | mov                 ebx, edx
            //   f7eb                 | imul                ebx
            //   c1fa02               | sar                 edx, 2
            //   8bc2                 | mov                 eax, edx

        $sequence_2 = { 57 8d8e2d010000 51 8dbeb1060000 57 ff9681000000 }
            // n = 6, score = 100
            //   57                   | push                edi
            //   8d8e2d010000         | lea                 ecx, dword ptr [esi + 0x12d]
            //   51                   | push                ecx
            //   8dbeb1060000         | lea                 edi, dword ptr [esi + 0x6b1]
            //   57                   | push                edi
            //   ff9681000000         | call                dword ptr [esi + 0x81]

        $sequence_3 = { 7265 6e 7456 657273 696f6e5c457870 6c 6f }
            // n = 7, score = 100
            //   7265                 | jb                  0x67
            //   6e                   | outsb               dx, byte ptr [esi]
            //   7456                 | je                  0x58
            //   657273               | jb                  0x76
            //   696f6e5c457870       | imul                ebp, dword ptr [edi + 0x6e], 0x7078455c
            //   6c                   | insb                byte ptr es:[edi], dx
            //   6f                   | outsd               dx, dword ptr [esi]

        $sequence_4 = { 837dfc01 7419 66c7075c00 68f4010000 ff96a5000000 8345fc01 e9???????? }
            // n = 7, score = 100
            //   837dfc01             | cmp                 dword ptr [ebp - 4], 1
            //   7419                 | je                  0x1b
            //   66c7075c00           | mov                 word ptr [edi], 0x5c
            //   68f4010000           | push                0x1f4
            //   ff96a5000000         | call                dword ptr [esi + 0xa5]
            //   8345fc01             | add                 dword ptr [ebp - 4], 1
            //   e9????????           |                     

        $sequence_5 = { 56 ff96d1000000 8d8d84f0ffff 51 6a00 50 ffb7d5000000 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   ff96d1000000         | call                dword ptr [esi + 0xd1]
            //   8d8d84f0ffff         | lea                 ecx, dword ptr [ebp - 0xf7c]
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   50                   | push                eax
            //   ffb7d5000000         | push                dword ptr [edi + 0xd5]

        $sequence_6 = { 57 ff7510 ff7514 50 ff750c ff96b5000000 58 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   50                   | push                eax
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff96b5000000         | call                dword ptr [esi + 0xb5]
            //   58                   | pop                 eax

        $sequence_7 = { 6800020000 50 56 ff15???????? 8945d8 }
            // n = 5, score = 100
            //   6800020000           | push                0x200
            //   50                   | push                eax
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax

        $sequence_8 = { 8d55ec 6a00 52 8d85c0fdffff }
            // n = 4, score = 100
            //   8d55ec               | lea                 edx, dword ptr [ebp - 0x14]
            //   6a00                 | push                0
            //   52                   | push                edx
            //   8d85c0fdffff         | lea                 eax, dword ptr [ebp - 0x240]

        $sequence_9 = { 50 57 ff9681000000 8d8665010000 50 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   57                   | push                edi
            //   ff9681000000         | call                dword ptr [esi + 0x81]
            //   8d8665010000         | lea                 eax, dword ptr [esi + 0x165]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 98304
}