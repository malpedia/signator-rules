rule win_crypmic_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.crypmic."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crypmic"
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
        $sequence_0 = { 8a5601 46 33c1 84d2 75e5 8b4df8 }
            // n = 6, score = 300
            //   8a5601               | mov                 dl, byte ptr [esi + 1]
            //   46                   | inc                 esi
            //   33c1                 | xor                 eax, ecx
            //   84d2                 | test                dl, dl
            //   75e5                 | jne                 0xffffffe7
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]

        $sequence_1 = { c3 8b55fc 5f 8b4224 }
            // n = 4, score = 300
            //   c3                   | ret                 
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   5f                   | pop                 edi
            //   8b4224               | mov                 eax, dword ptr [edx + 0x24]

        $sequence_2 = { ffd0 8b45e8 5f 03c6 5e 5b }
            // n = 6, score = 300
            //   ffd0                 | call                eax
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   5f                   | pop                 edi
            //   03c6                 | add                 eax, esi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_3 = { 8d048528000000 50 8b4608 6a08 ff7604 ffd0 }
            // n = 6, score = 300
            //   8d048528000000       | lea                 eax, dword ptr [eax*4 + 0x28]
            //   50                   | push                eax
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   6a08                 | push                8
            //   ff7604               | push                dword ptr [esi + 4]
            //   ffd0                 | call                eax

        $sequence_4 = { 8bec 83ec10 837d0800 8bc2 }
            // n = 4, score = 300
            //   8bec                 | mov                 ebp, esp
            //   83ec10               | sub                 esp, 0x10
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   8bc2                 | mov                 eax, edx

        $sequence_5 = { 50 8b4608 6a08 ff7604 ffd0 }
            // n = 5, score = 300
            //   50                   | push                eax
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   6a08                 | push                8
            //   ff7604               | push                dword ptr [esi + 4]
            //   ffd0                 | call                eax

        $sequence_6 = { 75f6 8d3c72 33c0 b952000000 33d2 }
            // n = 5, score = 300
            //   75f6                 | jne                 0xfffffff8
            //   8d3c72               | lea                 edi, dword ptr [edx + esi*2]
            //   33c0                 | xor                 eax, eax
            //   b952000000           | mov                 ecx, 0x52
            //   33d2                 | xor                 edx, edx

        $sequence_7 = { 0fb70c08 8b421c 8d0488 8b4df8 8b0408 }
            // n = 5, score = 300
            //   0fb70c08             | movzx               ecx, word ptr [eax + ecx]
            //   8b421c               | mov                 eax, dword ptr [edx + 0x1c]
            //   8d0488               | lea                 eax, dword ptr [eax + ecx*4]
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   8b0408               | mov                 eax, dword ptr [eax + ecx]

        $sequence_8 = { 8b470c 6a00 ff7704 ffd0 }
            // n = 4, score = 300
            //   8b470c               | mov                 eax, dword ptr [edi + 0xc]
            //   6a00                 | push                0
            //   ff7704               | push                dword ptr [edi + 4]
            //   ffd0                 | call                eax

        $sequence_9 = { 50 8b4608 6a08 ff7604 ffd0 8bf8 c70728000000 }
            // n = 7, score = 300
            //   50                   | push                eax
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   6a08                 | push                8
            //   ff7604               | push                dword ptr [esi + 4]
            //   ffd0                 | call                eax
            //   8bf8                 | mov                 edi, eax
            //   c70728000000         | mov                 dword ptr [edi], 0x28

    condition:
        7 of them and filesize < 81920
}