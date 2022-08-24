rule win_bumblebee_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-08-05"
        version = "1"
        description = "Detects win.bumblebee."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bumblebee"
        malpedia_rule_date = "20220805"
        malpedia_hash = "6ec06c64bcfdbeda64eff021c766b4ce34542b71"
        malpedia_version = "20220808"
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
        $sequence_0 = { 668908 4c8975af 4c8975b7 48c745b70f000000 4c8975af c6459f00 803b00 }
            // n = 7, score = 1400
            //   668908               | mov                 dword ptr [ebp + 0x28], edi
            //   4c8975af             | test                eax, eax
            //   4c8975b7             | je                  0x73d
            //   48c745b70f000000     | dec                 eax
            //   4c8975af             | mov                 dword ptr [esp + 0x68], esi
            //   c6459f00             | dec                 eax
            //   803b00               | lea                 ecx, [0x44c89]

        $sequence_1 = { 48ba0026000001000000 488b4c2428 0f1f00 0fb601 3c20 7714 480fbec0 }
            // n = 7, score = 1400
            //   48ba0026000001000000     | dec    eax
            //   488b4c2428           | lea                 edx, [0x1212d5]
            //   0f1f00               | dec                 eax
            //   0fb601               | mov                 ecx, ebx
            //   3c20                 | dec                 esp
            //   7714                 | mov                 eax, edi
            //   480fbec0             | dec                 eax

        $sequence_2 = { b90e000780 e8???????? 90 488b4c2450 488b01 4c8d45d8 488b13 }
            // n = 7, score = 1400
            //   b90e000780           | lea                 eax, [edx - 0x4c]
            //   e8????????           |                     
            //   90                   | jne                 0xb52
            //   488b4c2450           | mov                 edx, 0x196
            //   488b01               | inc                 ecx
            //   4c8d45d8             | mov                 dword ptr [ecx], 0x28
            //   488b13               | dec                 esp

        $sequence_3 = { c744242000000000 488d442430 4889442470 488bd1 488d4c2430 e8???????? 90 }
            // n = 7, score = 1400
            //   c744242000000000     | add                 dword ptr [ebx + 0x18], 2
            //   488d442430           | or                  edi, 0xffffffff
            //   4889442470           | dec                 ebp
            //   488bd1               | mov                 esp, eax
            //   488d4c2430           | dec                 eax
            //   e8????????           |                     
            //   90                   | mov                 esi, edx

        $sequence_4 = { e8???????? cc 488bde 48895d60 4885db 750b b90e000780 }
            // n = 7, score = 1400
            //   e8????????           |                     
            //   cc                   | dec                 eax
            //   488bde               | lea                 eax, [0x19e844]
            //   48895d60             | dec                 eax
            //   4885db               | mov                 dword ptr [ebx], eax
            //   750b                 | dec                 eax
            //   b90e000780           | lea                 eax, [0x19e882]

        $sequence_5 = { 7541 4533f6 418bfe 0f1f8000000000 498d4dff 49d3e6 4d03f6 }
            // n = 7, score = 1400
            //   7541                 | dec                 esp
            //   4533f6               | lea                 ecx, [0x12107d]
            //   418bfe               | mov                 dword ptr [esp + 0x20], 0x52
            //   0f1f8000000000       | lea                 edx, [eax + 0x6a]
            //   498d4dff             | lea                 ecx, [eax + 4]
            //   49d3e6               | inc                 esp
            //   4d03f6               | lea                 eax, [eax + 0x41]

        $sequence_6 = { 90 488b4c2458 488b01 488b13 ff90b8000000 90 418bc6 }
            // n = 7, score = 1400
            //   90                   | inc                 ecx
            //   488b4c2458           | mov                 eax, 0x11
            //   488b01               | dec                 eax
            //   488b13               | lea                 edx, [0x7107b]
            //   ff90b8000000         | jmp                 0x1a96
            //   90                   | inc                 ecx
            //   418bc6               | cmp                 eax, 4

        $sequence_7 = { 7410 488b4608 4889442428 48895c2420 eb12 48c744242000000000 }
            // n = 6, score = 1400
            //   7410                 | dec                 esp
            //   488b4608             | lea                 esi, [0x111a71]
            //   4889442428           | inc                 esp
            //   48895c2420           | mov                 edx, eax
            //   eb12                 | dec                 eax
            //   48c744242000000000     | mov    edi, edx

        $sequence_8 = { 7404 48896f08 48895f08 4885db 740a 488b03 488bcb }
            // n = 7, score = 1400
            //   7404                 | je                  0x60b
            //   48896f08             | nop                 dword ptr [eax]
            //   48895f08             | dec                 eax
            //   4885db               | dec                 ecx
            //   740a                 | inc                 ebp
            //   488b03               | movzx               ecx, byte ptr [eax]
            //   488bcb               | dec                 esp

        $sequence_9 = { 7244 488b03 eb42 4885ff 75eb 48897910 4883791810 }
            // n = 7, score = 1400
            //   7244                 | mov                 dword ptr [esp + 0x98], edi
            //   488b03               | dec                 esp
            //   eb42                 | arpl                ax, di
            //   4885ff               | dec                 eax
            //   75eb                 | lea                 edx, [0x75a4f]
            //   48897910             | dec                 ecx
            //   4883791810           | mov                 ecx, edi

    condition:
        6 of them and filesize < 4825088
}
