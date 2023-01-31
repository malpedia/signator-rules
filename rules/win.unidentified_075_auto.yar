rule win_unidentified_075_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.unidentified_075."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_075"
        malpedia_rule_date = "20230124"
        malpedia_hash = "2ee0eebba83dce3d019a90519f2f972c0fcf9686"
        malpedia_version = "20230125"
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
        $sequence_0 = { 6a04 8d4d8c 51 6a05 8b55f4 52 }
            // n = 6, score = 200
            //   6a04                 | push                4
            //   8d4d8c               | lea                 ecx, [ebp - 0x74]
            //   51                   | push                ecx
            //   6a05                 | push                5
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   52                   | push                edx

        $sequence_1 = { b86e000000 668945c6 b96c000000 66894dc8 ba69000000 668955ca }
            // n = 6, score = 200
            //   b86e000000           | mov                 eax, 0x6e
            //   668945c6             | mov                 word ptr [ebp - 0x3a], ax
            //   b96c000000           | mov                 ecx, 0x6c
            //   66894dc8             | mov                 word ptr [ebp - 0x38], cx
            //   ba69000000           | mov                 edx, 0x69
            //   668955ca             | mov                 word ptr [ebp - 0x36], dx

        $sequence_2 = { c645c92d c645ca73 c645cb74 c645cc6f }
            // n = 4, score = 200
            //   c645c92d             | mov                 byte ptr [ebp - 0x37], 0x2d
            //   c645ca73             | mov                 byte ptr [ebp - 0x36], 0x73
            //   c645cb74             | mov                 byte ptr [ebp - 0x35], 0x74
            //   c645cc6f             | mov                 byte ptr [ebp - 0x34], 0x6f

        $sequence_3 = { 668955c4 b86e000000 668945c6 b96c000000 66894dc8 ba69000000 }
            // n = 6, score = 200
            //   668955c4             | mov                 word ptr [ebp - 0x3c], dx
            //   b86e000000           | mov                 eax, 0x6e
            //   668945c6             | mov                 word ptr [ebp - 0x3a], ax
            //   b96c000000           | mov                 ecx, 0x6c
            //   66894dc8             | mov                 word ptr [ebp - 0x38], cx
            //   ba69000000           | mov                 edx, 0x69

        $sequence_4 = { c645a265 c645a33f c645a477 c645a564 }
            // n = 4, score = 200
            //   c645a265             | mov                 byte ptr [ebp - 0x5e], 0x65
            //   c645a33f             | mov                 byte ptr [ebp - 0x5d], 0x3f
            //   c645a477             | mov                 byte ptr [ebp - 0x5c], 0x77
            //   c645a564             | mov                 byte ptr [ebp - 0x5b], 0x64

        $sequence_5 = { 51 8d95dcf6ffff 52 e8???????? 6a00 8d85ace6ffff 50 }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   8d95dcf6ffff         | lea                 edx, [ebp - 0x924]
            //   52                   | push                edx
            //   e8????????           |                     
            //   6a00                 | push                0
            //   8d85ace6ffff         | lea                 eax, [ebp - 0x1954]
            //   50                   | push                eax

        $sequence_6 = { 8b55fc 83c241 52 68???????? 8b45e8 }
            // n = 5, score = 200
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   83c241               | add                 edx, 0x41
            //   52                   | push                edx
            //   68????????           |                     
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]

        $sequence_7 = { 742c 8b4514 85c0 7421 }
            // n = 4, score = 200
            //   742c                 | je                  0x2e
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   85c0                 | test                eax, eax
            //   7421                 | je                  0x23

        $sequence_8 = { 83c410 8d85f4fcffff 50 e8???????? 83c404 6a00 }
            // n = 6, score = 200
            //   83c410               | add                 esp, 0x10
            //   8d85f4fcffff         | lea                 eax, [ebp - 0x30c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   6a00                 | push                0

        $sequence_9 = { 7546 c705????????01000000 c745fc00000000 eb09 8b45fc }
            // n = 5, score = 200
            //   7546                 | jne                 0x48
            //   c705????????01000000     |     
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   eb09                 | jmp                 0xb
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

    condition:
        7 of them and filesize < 393216
}