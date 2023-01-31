rule win_thumbthief_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.thumbthief."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.thumbthief"
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
        $sequence_0 = { ebac 834dfcff 33c0 8b7dc4 6689444ffe ff7310 e8???????? }
            // n = 7, score = 100
            //   ebac                 | jmp                 0xffffffae
            //   834dfcff             | or                  dword ptr [ebp - 4], 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   8b7dc4               | mov                 edi, dword ptr [ebp - 0x3c]
            //   6689444ffe           | mov                 word ptr [edi + ecx*2 - 2], ax
            //   ff7310               | push                dword ptr [ebx + 0x10]
            //   e8????????           |                     

        $sequence_1 = { ffd0 83c414 8bd8 85f6 7424 f6461840 8bce }
            // n = 7, score = 100
            //   ffd0                 | call                eax
            //   83c414               | add                 esp, 0x14
            //   8bd8                 | mov                 ebx, eax
            //   85f6                 | test                esi, esi
            //   7424                 | je                  0x26
            //   f6461840             | test                byte ptr [esi + 0x18], 0x40
            //   8bce                 | mov                 ecx, esi

        $sequence_2 = { c645fc02 8b750c 85f6 7526 68???????? 68???????? 8d8d38ffffff }
            // n = 7, score = 100
            //   c645fc02             | mov                 byte ptr [ebp - 4], 2
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   85f6                 | test                esi, esi
            //   7526                 | jne                 0x28
            //   68????????           |                     
            //   68????????           |                     
            //   8d8d38ffffff         | lea                 ecx, [ebp - 0xc8]

        $sequence_3 = { ff7624 8b4620 ffd0 83c408 85c0 7409 83f805 }
            // n = 7, score = 100
            //   ff7624               | push                dword ptr [esi + 0x24]
            //   8b4620               | mov                 eax, dword ptr [esi + 0x20]
            //   ffd0                 | call                eax
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   7409                 | je                  0xb
            //   83f805               | cmp                 eax, 5

        $sequence_4 = { eb02 33c9 46 894c2434 8d0448 03f0 83fe46 }
            // n = 7, score = 100
            //   eb02                 | jmp                 4
            //   33c9                 | xor                 ecx, ecx
            //   46                   | inc                 esi
            //   894c2434             | mov                 dword ptr [esp + 0x34], ecx
            //   8d0448               | lea                 eax, [eax + ecx*2]
            //   03f0                 | add                 esi, eax
            //   83fe46               | cmp                 esi, 0x46

        $sequence_5 = { ff74241c ba15000000 8bce e8???????? 83c404 8b542408 33c9 }
            // n = 7, score = 100
            //   ff74241c             | push                dword ptr [esp + 0x1c]
            //   ba15000000           | mov                 edx, 0x15
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b542408             | mov                 edx, dword ptr [esp + 8]
            //   33c9                 | xor                 ecx, ecx

        $sequence_6 = { fec8 884713 0fb6c0 8b44871c 50 6a00 ba0a000000 }
            // n = 7, score = 100
            //   fec8                 | dec                 al
            //   884713               | mov                 byte ptr [edi + 0x13], al
            //   0fb6c0               | movzx               eax, al
            //   8b44871c             | mov                 eax, dword ptr [edi + eax*4 + 0x1c]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ba0a000000           | mov                 edx, 0xa

        $sequence_7 = { e9???????? 8d8df4feffff e9???????? 8d8d1cffffff e9???????? 8d8d08ffffff e9???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8d8df4feffff         | lea                 ecx, [ebp - 0x10c]
            //   e9????????           |                     
            //   8d8d1cffffff         | lea                 ecx, [ebp - 0xe4]
            //   e9????????           |                     
            //   8d8d08ffffff         | lea                 ecx, [ebp - 0xf8]
            //   e9????????           |                     

        $sequence_8 = { e8???????? c645fc00 33c0 8b55bc 8bca 8b5dc0 8bfb }
            // n = 7, score = 100
            //   e8????????           |                     
            //   c645fc00             | mov                 byte ptr [ebp - 4], 0
            //   33c0                 | xor                 eax, eax
            //   8b55bc               | mov                 edx, dword ptr [ebp - 0x44]
            //   8bca                 | mov                 ecx, edx
            //   8b5dc0               | mov                 ebx, dword ptr [ebp - 0x40]
            //   8bfb                 | mov                 edi, ebx

        $sequence_9 = { c645fc01 e8???????? c645fc02 8d4508 c7473c00000000 8d4f44 c7474000000000 }
            // n = 7, score = 100
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   e8????????           |                     
            //   c645fc02             | mov                 byte ptr [ebp - 4], 2
            //   8d4508               | lea                 eax, [ebp + 8]
            //   c7473c00000000       | mov                 dword ptr [edi + 0x3c], 0
            //   8d4f44               | lea                 ecx, [edi + 0x44]
            //   c7474000000000       | mov                 dword ptr [edi + 0x40], 0

    condition:
        7 of them and filesize < 4235264
}