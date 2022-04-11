rule win_lethic_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.lethic."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lethic"
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
        $sequence_0 = { 8b4dfc 83c108 51 8b55f4 }
            // n = 4, score = 1200
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   83c108               | add                 ecx, 8
            //   51                   | push                ecx
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]

        $sequence_1 = { 8955f8 8b45f8 034510 8945f4 8b4df8 3b4df4 741e }
            // n = 7, score = 1200
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   034510               | add                 eax, dword ptr [ebp + 0x10]
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   3b4df4               | cmp                 ecx, dword ptr [ebp - 0xc]
            //   741e                 | je                  0x20

        $sequence_2 = { 8b4d10 894804 8b55fc c7823410000001000000 6a10 }
            // n = 5, score = 1200
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   894804               | mov                 dword ptr [eax + 4], ecx
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   c7823410000001000000     | mov    dword ptr [edx + 0x1034], 1
            //   6a10                 | push                0x10

        $sequence_3 = { 894df8 8b55fc 3b55f8 7411 8b45fc }
            // n = 5, score = 1200
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   3b55f8               | cmp                 edx, dword ptr [ebp - 8]
            //   7411                 | je                  0x13
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_4 = { 8b45fc 8b08 894dfc ebec 8b55fc 8b45f4 8b08 }
            // n = 7, score = 1200
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   ebec                 | jmp                 0xffffffee
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_5 = { 837a18ff 7420 8d45f8 50 }
            // n = 4, score = 1200
            //   837a18ff             | cmp                 dword ptr [edx + 0x18], -1
            //   7420                 | je                  0x22
            //   8d45f8               | lea                 eax, dword ptr [ebp - 8]
            //   50                   | push                eax

        $sequence_6 = { 8b08 894dfc ebec 8b55fc 8b45f4 8b08 }
            // n = 6, score = 1200
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   ebec                 | jmp                 0xffffffee
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_7 = { 8945fc 8b4dfc 894df0 8b550c 8955f8 }
            // n = 5, score = 1200
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   894df0               | mov                 dword ptr [ebp - 0x10], ecx
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   8955f8               | mov                 dword ptr [ebp - 8], edx

        $sequence_8 = { 8945f8 8b4d0c 894df4 837df400 7507 33c0 }
            // n = 6, score = 1200
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   837df400             | cmp                 dword ptr [ebp - 0xc], 0
            //   7507                 | jne                 9
            //   33c0                 | xor                 eax, eax

        $sequence_9 = { 6a10 8b450c 50 8b4dfc 83c108 }
            // n = 5, score = 1200
            //   6a10                 | push                0x10
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   83c108               | add                 ecx, 8

    condition:
        7 of them and filesize < 81920
}