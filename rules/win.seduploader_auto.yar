rule win_seduploader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.seduploader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.seduploader"
        malpedia_rule_date = "20211007"
        malpedia_hash = "e5b790e0f888f252d49063a1251ca60ec2832535"
        malpedia_version = "20211008"
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
        $sequence_0 = { 8bf0 eb02 33f6 8bce e8???????? 85f6 740e }
            // n = 7, score = 1700
            //   8bf0                 | mov                 esi, eax
            //   eb02                 | jmp                 4
            //   33f6                 | xor                 esi, esi
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   85f6                 | test                esi, esi
            //   740e                 | je                  0x10

        $sequence_1 = { 57 33db c745fc01000000 8d7d08 85f6 }
            // n = 5, score = 1700
            //   57                   | push                edi
            //   33db                 | xor                 ebx, ebx
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   8d7d08               | lea                 edi, dword ptr [ebp + 8]
            //   85f6                 | test                esi, esi

        $sequence_2 = { 6a32 ff7510 8bf0 56 e8???????? }
            // n = 5, score = 1700
            //   6a32                 | push                0x32
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   8bf0                 | mov                 esi, eax
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_3 = { eb8f be???????? eb88 be???????? eb81 }
            // n = 5, score = 1700
            //   eb8f                 | jmp                 0xffffff91
            //   be????????           |                     
            //   eb88                 | jmp                 0xffffff8a
            //   be????????           |                     
            //   eb81                 | jmp                 0xffffff83

        $sequence_4 = { ff7510 a3???????? e8???????? 50 ff7510 }
            // n = 5, score = 1700
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   a3????????           |                     
            //   e8????????           |                     
            //   50                   | push                eax
            //   ff7510               | push                dword ptr [ebp + 0x10]

        $sequence_5 = { 83c40c 3b4508 740c 8b36 3bf7 75e3 }
            // n = 6, score = 1700
            //   83c40c               | add                 esp, 0xc
            //   3b4508               | cmp                 eax, dword ptr [ebp + 8]
            //   740c                 | je                  0xe
            //   8b36                 | mov                 esi, dword ptr [esi]
            //   3bf7                 | cmp                 esi, edi
            //   75e3                 | jne                 0xffffffe5

        $sequence_6 = { e8???????? 57 e8???????? 59 8b3e 85ff 740e }
            // n = 7, score = 1700
            //   e8????????           |                     
            //   57                   | push                edi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8b3e                 | mov                 edi, dword ptr [esi]
            //   85ff                 | test                edi, edi
            //   740e                 | je                  0x10

        $sequence_7 = { 7434 e8???????? 8945fc 0336 }
            // n = 4, score = 1700
            //   7434                 | je                  0x36
            //   e8????????           |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   0336                 | add                 esi, dword ptr [esi]

        $sequence_8 = { c3 55 8bec 68e3010000 68d73d5908 6a08 }
            // n = 6, score = 1700
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   68e3010000           | push                0x1e3
            //   68d73d5908           | push                0x8593dd7
            //   6a08                 | push                8

        $sequence_9 = { 6840771b00 e9???????? 55 8bec }
            // n = 4, score = 1400
            //   6840771b00           | push                0x1b7740
            //   e9????????           |                     
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp

        $sequence_10 = { 59 59 6840771b00 e9???????? }
            // n = 4, score = 1300
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   6840771b00           | push                0x1b7740
            //   e9????????           |                     

        $sequence_11 = { 89450c 3bc3 7cdb 5f 8bc6 }
            // n = 5, score = 1000
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   3bc3                 | cmp                 eax, ebx
            //   7cdb                 | jl                  0xffffffdd
            //   5f                   | pop                 edi
            //   8bc6                 | mov                 eax, esi

        $sequence_12 = { e8???????? 8bf0 33c0 89450c 59 }
            // n = 5, score = 1000
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   33c0                 | xor                 eax, eax
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   59                   | pop                 ecx

        $sequence_13 = { 32040f 8801 8b450c 40 89450c 3bc3 }
            // n = 6, score = 1000
            //   32040f               | xor                 al, byte ptr [edi + ecx]
            //   8801                 | mov                 byte ptr [ecx], al
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   40                   | inc                 eax
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   3bc3                 | cmp                 eax, ebx

        $sequence_14 = { 7e2c 57 8b7d08 2bfe 8d0c30 }
            // n = 5, score = 1000
            //   7e2c                 | jle                 0x2e
            //   57                   | push                edi
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   2bfe                 | sub                 edi, esi
            //   8d0c30               | lea                 ecx, dword ptr [eax + esi]

        $sequence_15 = { 89450c 59 85db 7e2c 57 }
            // n = 5, score = 1000
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   59                   | pop                 ecx
            //   85db                 | test                ebx, ebx
            //   7e2c                 | jle                 0x2e
            //   57                   | push                edi

        $sequence_16 = { 753b 6a08 c70302000000 e8???????? 59 }
            // n = 5, score = 1000
            //   753b                 | jne                 0x3d
            //   6a08                 | push                8
            //   c70302000000         | mov                 dword ptr [ebx], 2
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_17 = { 8b5d0c 56 8d4301 50 e8???????? 8bf0 }
            // n = 6, score = 1000
            //   8b5d0c               | mov                 ebx, dword ptr [ebp + 0xc]
            //   56                   | push                esi
            //   8d4301               | lea                 eax, dword ptr [ebx + 1]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_18 = { 8bcf 53 e8???????? 89470c 3933 753b 6a08 }
            // n = 7, score = 500
            //   8bcf                 | mov                 ecx, edi
            //   53                   | push                ebx
            //   e8????????           |                     
            //   89470c               | mov                 dword ptr [edi + 0xc], eax
            //   3933                 | cmp                 dword ptr [ebx], esi
            //   753b                 | jne                 0x3d
            //   6a08                 | push                8

    condition:
        7 of them and filesize < 401408
}