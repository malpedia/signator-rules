rule win_xagent_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.xagent."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xagent"
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
        $sequence_0 = { c1ea02 6bd20d b801000000 2bc2 }
            // n = 4, score = 3100
            //   c1ea02               | shr                 edx, 2
            //   6bd20d               | imul                edx, edx, 0xd
            //   b801000000           | mov                 eax, 1
            //   2bc2                 | sub                 eax, edx

        $sequence_1 = { ff15???????? 8bd8 e8???????? 03d8 }
            // n = 4, score = 3100
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax
            //   e8????????           |                     
            //   03d8                 | add                 ebx, eax

        $sequence_2 = { 5d c20400 8d4de4 e8???????? b8???????? c3 }
            // n = 6, score = 2600
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]
            //   e8????????           |                     
            //   b8????????           |                     
            //   c3                   | ret                 

        $sequence_3 = { 03ff 3b7e0c 7707 c7460c00000000 49 }
            // n = 5, score = 2600
            //   03ff                 | add                 edi, edi
            //   3b7e0c               | cmp                 edi, dword ptr [esi + 0xc]
            //   7707                 | ja                  9
            //   c7460c00000000       | mov                 dword ptr [esi + 0xc], 0
            //   49                   | dec                 ecx

        $sequence_4 = { 8b4808 8bc1 57 8b7a08 c1e802 83e103 }
            // n = 6, score = 2600
            //   8b4808               | mov                 ecx, dword ptr [eax + 8]
            //   8bc1                 | mov                 eax, ecx
            //   57                   | push                edi
            //   8b7a08               | mov                 edi, dword ptr [edx + 8]
            //   c1e802               | shr                 eax, 2
            //   83e103               | and                 ecx, 3

        $sequence_5 = { 85c0 7407 8b4d08 8b11 8910 83460404 5e }
            // n = 7, score = 2600
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   8910                 | mov                 dword ptr [eax], edx
            //   83460404             | add                 dword ptr [esi + 4], 4
            //   5e                   | pop                 esi

        $sequence_6 = { ff15???????? 6a08 e8???????? 83c404 85c0 }
            // n = 5, score = 2600
            //   ff15????????         |                     
            //   6a08                 | push                8
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax

        $sequence_7 = { c7460c00000000 49 894e10 7507 c7460c00000000 }
            // n = 5, score = 2600
            //   c7460c00000000       | mov                 dword ptr [esi + 0xc], 0
            //   49                   | dec                 ecx
            //   894e10               | mov                 dword ptr [esi + 0x10], ecx
            //   7507                 | jne                 9
            //   c7460c00000000       | mov                 dword ptr [esi + 0xc], 0

        $sequence_8 = { 2bc7 8b5204 8b0482 8b0488 8b4e10 85c9 }
            // n = 6, score = 2600
            //   2bc7                 | sub                 eax, edi
            //   8b5204               | mov                 edx, dword ptr [edx + 4]
            //   8b0482               | mov                 eax, dword ptr [edx + eax*4]
            //   8b0488               | mov                 eax, dword ptr [eax + ecx*4]
            //   8b4e10               | mov                 ecx, dword ptr [esi + 0x10]
            //   85c9                 | test                ecx, ecx

        $sequence_9 = { 8b0488 8b4e10 85c9 7423 8b7e08 ff460c 03ff }
            // n = 7, score = 2600
            //   8b0488               | mov                 eax, dword ptr [eax + ecx*4]
            //   8b4e10               | mov                 ecx, dword ptr [esi + 0x10]
            //   85c9                 | test                ecx, ecx
            //   7423                 | je                  0x25
            //   8b7e08               | mov                 edi, dword ptr [esi + 8]
            //   ff460c               | inc                 dword ptr [esi + 0xc]
            //   03ff                 | add                 edi, edi

        $sequence_10 = { e8???????? 498bce 4e8d0437 482bcf }
            // n = 4, score = 1500
            //   e8????????           |                     
            //   498bce               | dec                 esp
            //   4e8d0437             | mov                 ecx, edi
            //   482bcf               | dec                 esp

        $sequence_11 = { e8???????? 488b4328 4c8bcf 4c8bc6 }
            // n = 4, score = 1500
            //   e8????????           |                     
            //   488b4328             | mov                 eax, dword ptr [edi]
            //   4c8bcf               | dec                 esp
            //   4c8bc6               | mov                 edx, dword ptr [ebx]

        $sequence_12 = { 84c0 740c 488b07 4c8b13 488903 4c8917 }
            // n = 6, score = 1500
            //   84c0                 | test                al, al
            //   740c                 | je                  0xe
            //   488b07               | dec                 eax
            //   4c8b13               | mov                 eax, dword ptr [edi]
            //   488903               | dec                 esp
            //   4c8917               | mov                 edx, dword ptr [ebx]

        $sequence_13 = { e8???????? 48833b00 740a 488b4308 }
            // n = 4, score = 1500
            //   e8????????           |                     
            //   48833b00             | mov                 dword ptr [edi], edx
            //   740a                 | dec                 eax
            //   488b4308             | mov                 edx, dword ptr [ebx]

        $sequence_14 = { 8bd8 e8???????? 8d0c18 e8???????? }
            // n = 4, score = 1500
            //   8bd8                 | dec                 eax
            //   e8????????           |                     
            //   8d0c18               | mov                 eax, dword ptr [ebx + 0x28]
            //   e8????????           |                     

        $sequence_15 = { 4883ec30 488b4118 488bd9 482b4110 48a9f8ffffff }
            // n = 5, score = 1500
            //   4883ec30             | imul                edx, edx, 0x95
            //   488b4118             | sub                 ecx, edx
            //   488bd9               | mov                 edx, ecx
            //   482b4110             | mov                 edx, 0x1f4
            //   48a9f8ffffff         | dec                 eax

        $sequence_16 = { e8???????? 488d542458 488bcb e8???????? 90 }
            // n = 5, score = 1500
            //   e8????????           |                     
            //   488d542458           | dec                 eax
            //   488bcb               | mov                 dword ptr [ebx], eax
            //   e8????????           |                     
            //   90                   | dec                 esp

        $sequence_17 = { 4885c0 740d 488bc8 e8???????? 4c8be0 eb03 4c8be3 }
            // n = 7, score = 1000
            //   4885c0               | cmp                 al, 1
            //   740d                 | jne                 6
            //   488bc8               | mov                 al, 1
            //   e8????????           |                     
            //   4c8be0               | jmp                 6
            //   eb03                 | xor                 al, al
            //   4c8be3               | cmp                 al, 1

        $sequence_18 = { ff15???????? baf4010000 488bcb ff15???????? }
            // n = 4, score = 600
            //   ff15????????         |                     
            //   baf4010000           | cmp                 al, 1
            //   488bcb               | dec                 eax
            //   ff15????????         |                     

        $sequence_19 = { b803b57ea5 f7e6 c1ea06 6bd263 }
            // n = 4, score = 500
            //   b803b57ea5           | test                eax, eax
            //   f7e6                 | je                  0xf
            //   c1ea06               | dec                 eax
            //   6bd263               | mov                 ecx, eax

        $sequence_20 = { c1ea07 69d295000000 2bca 8bd1 }
            // n = 4, score = 400
            //   c1ea07               | dec                 esp
            //   69d295000000         | mov                 esp, ebx
            //   2bca                 | je                  0xf
            //   8bd1                 | dec                 eax

        $sequence_21 = { 75f7 4c2bdb 458b4530 498b5528 }
            // n = 4, score = 200
            //   75f7                 | dec                 esp
            //   4c2bdb               | sub                 eax, edi
            //   458b4530             | cmp                 byte ptr [ebx], 0
            //   498b5528             | dec                 eax

        $sequence_22 = { 75f7 4c2bdb 458b4550 498b5548 }
            // n = 4, score = 200
            //   75f7                 | inc                 ecx
            //   4c2bdb               | mov                 edi, 0xa
            //   458b4550             | dec                 ebp
            //   498b5548             | mov                 eax, esi

        $sequence_23 = { 75f7 4c2bc7 803b00 488bc3 740f 0f1f8000000000 }
            // n = 6, score = 200
            //   75f7                 | jmp                 0xb
            //   4c2bc7               | dec                 esp
            //   803b00               | mov                 esp, ebx
            //   488bc3               | dec                 eax
            //   740f                 | mov                 ecx, eax
            //   0f1f8000000000       | dec                 esp

        $sequence_24 = { 75f7 4c2bdb 41bf0a000000 4d8bc6 }
            // n = 4, score = 200
            //   75f7                 | dec                 esp
            //   4c2bdb               | mov                 esp, ebx
            //   41bf0a000000         | mov                 edx, 0x1f4
            //   4d8bc6               | dec                 eax

    condition:
        7 of them and filesize < 729088
}