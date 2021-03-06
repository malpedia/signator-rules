rule win_xpan_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.xpan."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xpan"
        malpedia_rule_date = "20220513"
        malpedia_hash = "7f4b2229e6ae614d86d74917f6d5b41890e62a26"
        malpedia_version = "20220516"
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
        $sequence_0 = { 31c0 38c2 0f8463ffffff 8d4d08 e8???????? 807db200 0f84fa010000 }
            // n = 7, score = 400
            //   31c0                 | xor                 eax, eax
            //   38c2                 | cmp                 dl, al
            //   0f8463ffffff         | je                  0xffffff69
            //   8d4d08               | lea                 ecx, [ebp + 8]
            //   e8????????           |                     
            //   807db200             | cmp                 byte ptr [ebp - 0x4e], 0
            //   0f84fa010000         | je                  0x200

        $sequence_1 = { e8???????? 893c24 89442404 89f1 e8???????? 83ec08 8d65f4 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   893c24               | mov                 dword ptr [esp], edi
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   89f1                 | mov                 ecx, esi
            //   e8????????           |                     
            //   83ec08               | sub                 esp, 8
            //   8d65f4               | lea                 esp, [ebp - 0xc]

        $sequence_2 = { c7451000000000 b801000000 eb9d 897dc8 0fb67dd0 884dd0 e9???????? }
            // n = 7, score = 400
            //   c7451000000000       | mov                 dword ptr [ebp + 0x10], 0
            //   b801000000           | mov                 eax, 1
            //   eb9d                 | jmp                 0xffffff9f
            //   897dc8               | mov                 dword ptr [ebp - 0x38], edi
            //   0fb67dd0             | movzx               edi, byte ptr [ebp - 0x30]
            //   884dd0               | mov                 byte ptr [ebp - 0x30], cl
            //   e9????????           |                     

        $sequence_3 = { 09f0 0f8417040000 8b4304 8d4c2438 0fb7542416 895c2408 89cd }
            // n = 7, score = 400
            //   09f0                 | or                  eax, esi
            //   0f8417040000         | je                  0x41d
            //   8b4304               | mov                 eax, dword ptr [ebx + 4]
            //   8d4c2438             | lea                 ecx, [esp + 0x38]
            //   0fb7542416           | movzx               edx, word ptr [esp + 0x16]
            //   895c2408             | mov                 dword ptr [esp + 8], ebx
            //   89cd                 | mov                 ebp, ecx

        $sequence_4 = { 891d???????? a3???????? 89c6 e9???????? 39c7 89442414 750e }
            // n = 7, score = 400
            //   891d????????         |                     
            //   a3????????           |                     
            //   89c6                 | mov                 esi, eax
            //   e9????????           |                     
            //   39c7                 | cmp                 edi, eax
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   750e                 | jne                 0x10

        $sequence_5 = { 0fb654241b 8b4c241c 7462 85ff 749a 8b442440 b901000000 }
            // n = 7, score = 400
            //   0fb654241b           | movzx               edx, byte ptr [esp + 0x1b]
            //   8b4c241c             | mov                 ecx, dword ptr [esp + 0x1c]
            //   7462                 | je                  0x64
            //   85ff                 | test                edi, edi
            //   749a                 | je                  0xffffff9c
            //   8b442440             | mov                 eax, dword ptr [esp + 0x40]
            //   b901000000           | mov                 ecx, 1

        $sequence_6 = { 83c701 895e04 892e 893d???????? 83c42c 89d0 5b }
            // n = 7, score = 400
            //   83c701               | add                 edi, 1
            //   895e04               | mov                 dword ptr [esi + 4], ebx
            //   892e                 | mov                 dword ptr [esi], ebp
            //   893d????????         |                     
            //   83c42c               | add                 esp, 0x2c
            //   89d0                 | mov                 eax, edx
            //   5b                   | pop                 ebx

        $sequence_7 = { 668951fe 75e3 31ed b801000000 668969fe b901000000 bd7a000780 }
            // n = 7, score = 400
            //   668951fe             | mov                 word ptr [ecx - 2], dx
            //   75e3                 | jne                 0xffffffe5
            //   31ed                 | xor                 ebp, ebp
            //   b801000000           | mov                 eax, 1
            //   668969fe             | mov                 word ptr [ecx - 2], bp
            //   b901000000           | mov                 ecx, 1
            //   bd7a000780           | mov                 ebp, 0x8007007a

        $sequence_8 = { e9???????? 8d489f 80f905 0f874b0e0000 83e857 e9???????? 8b931c010000 }
            // n = 7, score = 400
            //   e9????????           |                     
            //   8d489f               | lea                 ecx, [eax - 0x61]
            //   80f905               | cmp                 cl, 5
            //   0f874b0e0000         | ja                  0xe51
            //   83e857               | sub                 eax, 0x57
            //   e9????????           |                     
            //   8b931c010000         | mov                 edx, dword ptr [ebx + 0x11c]

        $sequence_9 = { 85f6 7417 85db 7413 f744245800100000 7409 }
            // n = 6, score = 400
            //   85f6                 | test                esi, esi
            //   7417                 | je                  0x19
            //   85db                 | test                ebx, ebx
            //   7413                 | je                  0x15
            //   f744245800100000     | test                dword ptr [esp + 0x58], 0x1000
            //   7409                 | je                  0xb

    condition:
        7 of them and filesize < 3235840
}