rule win_icondown_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.icondown."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.icondown"
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
        $sequence_0 = { ff15???????? c3 c20400 b8???????? c3 8b01 ff10 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   c3                   | ret                 
            //   c20400               | ret                 4
            //   b8????????           |                     
            //   c3                   | ret                 
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   ff10                 | call                dword ptr [eax]

        $sequence_1 = { 0fafd7 f7ea c1fa05 8bc2 c1e81f 03d0 b81f85eb51 }
            // n = 7, score = 200
            //   0fafd7               | imul                edx, edi
            //   f7ea                 | imul                edx
            //   c1fa05               | sar                 edx, 5
            //   8bc2                 | mov                 eax, edx
            //   c1e81f               | shr                 eax, 0x1f
            //   03d0                 | add                 edx, eax
            //   b81f85eb51           | mov                 eax, 0x51eb851f

        $sequence_2 = { 5b c20400 8b968c000000 6a00 6a00 6804130000 }
            // n = 6, score = 200
            //   5b                   | pop                 ebx
            //   c20400               | ret                 4
            //   8b968c000000         | mov                 edx, dword ptr [esi + 0x8c]
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6804130000           | push                0x1304

        $sequence_3 = { e8???????? 8bf8 8b06 8bce ff90c4000000 8bc7 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8bce                 | mov                 ecx, esi
            //   ff90c4000000         | call                dword ptr [eax + 0xc4]
            //   8bc7                 | mov                 eax, edi

        $sequence_4 = { 50 57 e8???????? 81c680000000 56 }
            // n = 5, score = 200
            //   50                   | push                eax
            //   57                   | push                edi
            //   e8????????           |                     
            //   81c680000000         | add                 esi, 0x80
            //   56                   | push                esi

        $sequence_5 = { 7732 8a4a02 8a5a03 3acb 7728 57 8b38 }
            // n = 7, score = 200
            //   7732                 | ja                  0x34
            //   8a4a02               | mov                 cl, byte ptr [edx + 2]
            //   8a5a03               | mov                 bl, byte ptr [edx + 3]
            //   3acb                 | cmp                 cl, bl
            //   7728                 | ja                  0x2a
            //   57                   | push                edi
            //   8b38                 | mov                 edi, dword ptr [eax]

        $sequence_6 = { 8bce e8???????? 33d2 33ff 8bc3 8b5c2410 }
            // n = 6, score = 200
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   33d2                 | xor                 edx, edx
            //   33ff                 | xor                 edi, edi
            //   8bc3                 | mov                 eax, ebx
            //   8b5c2410             | mov                 ebx, dword ptr [esp + 0x10]

        $sequence_7 = { 89bc89641e4500 8b0d???????? c1e102 898489681e4500 a1???????? c1e002 c784806c1e450001000000 }
            // n = 7, score = 200
            //   89bc89641e4500       | mov                 dword ptr [ecx + ecx*4 + 0x451e64], edi
            //   8b0d????????         |                     
            //   c1e102               | shl                 ecx, 2
            //   898489681e4500       | mov                 dword ptr [ecx + ecx*4 + 0x451e68], eax
            //   a1????????           |                     
            //   c1e002               | shl                 eax, 2
            //   c784806c1e450001000000     | mov    dword ptr [eax + eax*4 + 0x451e6c], 1

        $sequence_8 = { 8b4908 85c9 75f4 32c0 c20400 85c9 7406 }
            // n = 7, score = 200
            //   8b4908               | mov                 ecx, dword ptr [ecx + 8]
            //   85c9                 | test                ecx, ecx
            //   75f4                 | jne                 0xfffffff6
            //   32c0                 | xor                 al, al
            //   c20400               | ret                 4
            //   85c9                 | test                ecx, ecx
            //   7406                 | je                  8

        $sequence_9 = { 8d4c2468 50 51 ff15???????? e8???????? 68???????? e8???????? }
            // n = 7, score = 200
            //   8d4c2468             | lea                 ecx, dword ptr [esp + 0x68]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   e8????????           |                     
            //   68????????           |                     
            //   e8????????           |                     

    condition:
        7 of them and filesize < 5505024
}