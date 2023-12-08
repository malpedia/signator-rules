rule win_lpeclient_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.lpeclient."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lpeclient"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
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
        $sequence_0 = { f0ff03 8bce e8???????? eb2b 83f8ff 7526 4c8d2567f60000 }
            // n = 7, score = 100
            //   f0ff03               | dec                 eax
            //   8bce                 | inc                 edx
            //   e8????????           |                     
            //   eb2b                 | movzx               eax, byte ptr [edx]
            //   83f8ff               | dec                 eax
            //   7526                 | inc                 edx
            //   4c8d2567f60000       | mov                 byte ptr [ecx + edx - 1], al

        $sequence_1 = { 33c0 80f90a 0f94c0 8944244c 488d054a1b0100 }
            // n = 5, score = 100
            //   33c0                 | dec                 eax
            //   80f90a               | sub                 esp, 0x50
            //   0f94c0               | cmp                 dword ptr [ecx + 0x1c], 0
            //   8944244c             | dec                 eax
            //   488d054a1b0100       | mov                 ebx, ecx

        $sequence_2 = { 33c0 488bfe 66f2af 48f7d1 48ffc9 0f8456010000 }
            // n = 6, score = 100
            //   33c0                 | mov                 dword ptr [ecx], eax
            //   488bfe               | dec                 eax
            //   66f2af               | lea                 eax, [0x11bab]
            //   48f7d1               | cmp                 dword ptr [ecx + 0x14], ebx
            //   48ffc9               | dec                 edx
            //   0f8456010000         | mov                 ecx, dword ptr [eax]

        $sequence_3 = { e8???????? c1eb03 85db 0f8e52130000 8b4c2450 8b542450 4c8d5e02 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   c1eb03               | lea                 ecx, [ebp - 0x80]
            //   85db                 | inc                 esp
            //   0f8e52130000         | mov                 eax, eax
            //   8b4c2450             | je                  0x561
            //   8b542450             | dec                 esp
            //   4c8d5e02             | lea                 ecx, [esp + 0x48]

        $sequence_4 = { 498be3 5f c3 48895c2410 4889742418 57 4881ec30020000 }
            // n = 7, score = 100
            //   498be3               | jmp                 0x2a
            //   5f                   | jne                 0x3b
            //   c3                   | mov                 ecx, dword ptr [ebx + 0x10]
            //   48895c2410           | inc                 ecx
            //   4889742418           | movzx               eax, bp
            //   57                   | cmp                 eax, ecx
            //   4881ec30020000       | jb                  0x72

        $sequence_5 = { 7406 81f1783bf682 48ffc7 48ffca 75e6 443bc1 410f94c5 }
            // n = 7, score = 100
            //   7406                 | mov                 dword ptr [esp + 0x40], edi
            //   81f1783bf682         | mov                 word ptr [ebp - 0x26], ax
            //   48ffc7               | mov                 eax, 0x53
            //   48ffca               | mov                 dword ptr [ebp - 0x22], 0x54
            //   75e6                 | mov                 word ptr [ebp - 0x24], ax
            //   443bc1               | mov                 eax, 0x4b
            //   410f94c5             | mov                 dword ptr [esp + 0x40], edi

        $sequence_6 = { 0fb64c38ff 4132c8 880a 4183c10b 41ffc2 }
            // n = 5, score = 100
            //   0fb64c38ff           | dec                 eax
            //   4132c8               | lea                 edx, [esp + 0xe0]
            //   880a                 | dec                 eax
            //   4183c10b             | lea                 ecx, [esp + 0x50]
            //   41ffc2               | dec                 esp

        $sequence_7 = { 0bd8 418b0424 8d0c03 8bfb 448bc1 48c1e918 83e10f }
            // n = 7, score = 100
            //   0bd8                 | inc                 esp
            //   418b0424             | movzx               eax, word ptr [ebp - 0x4c]
            //   8d0c03               | dec                 eax
            //   8bfb                 | mov                 edx, dword ptr [ebp - 0x58]
            //   448bc1               | dec                 eax
            //   48c1e918             | mov                 dword ptr [esp + 0x38], esi
            //   83e10f               | mov                 dword ptr [esp + 0x30], esi

        $sequence_8 = { 488d0d0f570100 ff15???????? 4c8b4308 488d1546e90000 488d0df74e0100 ff15???????? 488d0d9a480100 }
            // n = 7, score = 100
            //   488d0d0f570100       | dec                 esp
            //   ff15????????         |                     
            //   4c8b4308             | arpl                bx, bx
            //   488d1546e90000       | xor                 eax, eax
            //   488d0df74e0100       | dec                 esp
            //   ff15????????         |                     
            //   488d0d9a480100       | arpl                bx, bx

        $sequence_9 = { 33db c74424646b000000 ff15???????? 448d4b01 448d4307 488d95a00b0000 }
            // n = 6, score = 100
            //   33db                 | je                  0x1f5f
            //   c74424646b000000     | mov                 edx, 1
            //   ff15????????         |                     
            //   448d4b01             | dec                 eax
            //   448d4307             | lea                 ecx, [0xffffcddf]
            //   488d95a00b0000       | and                 eax, 0xf

    condition:
        7 of them and filesize < 289792
}