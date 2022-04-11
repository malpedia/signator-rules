rule win_backconfig_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.backconfig."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.backconfig"
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
        $sequence_0 = { 8d3c85c0504100 8b07 c1e606 f644300401 7436 }
            // n = 5, score = 100
            //   8d3c85c0504100       | lea                 edi, dword ptr [eax*4 + 0x4150c0]
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   c1e606               | shl                 esi, 6
            //   f644300401           | test                byte ptr [eax + esi + 4], 1
            //   7436                 | je                  0x38

        $sequence_1 = { 68???????? 52 e8???????? 83c410 6a0a }
            // n = 5, score = 100
            //   68????????           |                     
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   6a0a                 | push                0xa

        $sequence_2 = { 8bc8 83e01f c1f905 8b0c8dc0504100 c1e006 8d440104 8020fe }
            // n = 7, score = 100
            //   8bc8                 | mov                 ecx, eax
            //   83e01f               | and                 eax, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   8b0c8dc0504100       | mov                 ecx, dword ptr [ecx*4 + 0x4150c0]
            //   c1e006               | shl                 eax, 6
            //   8d440104             | lea                 eax, dword ptr [ecx + eax + 4]
            //   8020fe               | and                 byte ptr [eax], 0xfe

        $sequence_3 = { 84d2 75f9 2bc6 741e }
            // n = 4, score = 100
            //   84d2                 | test                dl, dl
            //   75f9                 | jne                 0xfffffffb
            //   2bc6                 | sub                 eax, esi
            //   741e                 | je                  0x20

        $sequence_4 = { c78504fdffff0031a004 ff15???????? 8bf8 6a05 8d8504fdffff 50 }
            // n = 6, score = 100
            //   c78504fdffff0031a004     | mov    dword ptr [ebp - 0x2fc], 0x4a03100
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   6a05                 | push                5
            //   8d8504fdffff         | lea                 eax, dword ptr [ebp - 0x2fc]
            //   50                   | push                eax

        $sequence_5 = { 33c0 39b8582a4100 0f8491000000 ff45e4 }
            // n = 4, score = 100
            //   33c0                 | xor                 eax, eax
            //   39b8582a4100         | cmp                 dword ptr [eax + 0x412a58], edi
            //   0f8491000000         | je                  0x97
            //   ff45e4               | inc                 dword ptr [ebp - 0x1c]

        $sequence_6 = { 8d1485c0504100 8b0a 83e61f c1e606 03ce 8a4124 }
            // n = 6, score = 100
            //   8d1485c0504100       | lea                 edx, dword ptr [eax*4 + 0x4150c0]
            //   8b0a                 | mov                 ecx, dword ptr [edx]
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   03ce                 | add                 ecx, esi
            //   8a4124               | mov                 al, byte ptr [ecx + 0x24]

        $sequence_7 = { 8b5dd0 ebab c745e46ce14000 817de478e14000 7311 8b45e4 }
            // n = 6, score = 100
            //   8b5dd0               | mov                 ebx, dword ptr [ebp - 0x30]
            //   ebab                 | jmp                 0xffffffad
            //   c745e46ce14000       | mov                 dword ptr [ebp - 0x1c], 0x40e16c
            //   817de478e14000       | cmp                 dword ptr [ebp - 0x1c], 0x40e178
            //   7311                 | jae                 0x13
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]

        $sequence_8 = { 833cf55422410001 751d 8d04f550224100 8938 68a00f0000 ff30 }
            // n = 6, score = 100
            //   833cf55422410001     | cmp                 dword ptr [esi*8 + 0x412254], 1
            //   751d                 | jne                 0x1f
            //   8d04f550224100       | lea                 eax, dword ptr [esi*8 + 0x412250]
            //   8938                 | mov                 dword ptr [eax], edi
            //   68a00f0000           | push                0xfa0
            //   ff30                 | push                dword ptr [eax]

        $sequence_9 = { 57 33ff ffb700264100 ff15???????? 898700264100 }
            // n = 5, score = 100
            //   57                   | push                edi
            //   33ff                 | xor                 edi, edi
            //   ffb700264100         | push                dword ptr [edi + 0x412600]
            //   ff15????????         |                     
            //   898700264100         | mov                 dword ptr [edi + 0x412600], eax

    condition:
        7 of them and filesize < 217088
}