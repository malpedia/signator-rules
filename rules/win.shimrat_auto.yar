rule win_shimrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.shimrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shimrat"
        malpedia_rule_date = "20221118"
        malpedia_hash = "e0702e2e6d1d00da65c8a29a4ebacd0a4c59e1af"
        malpedia_version = "20221125"
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
        $sequence_0 = { 85c0 751e 8d4570 50 }
            // n = 4, score = 100
            //   85c0                 | test                eax, eax
            //   751e                 | jne                 0x20
            //   8d4570               | lea                 eax, [ebp + 0x70]
            //   50                   | push                eax

        $sequence_1 = { 8bf9 8d4df4 e8???????? 8d4de8 e8???????? }
            // n = 5, score = 100
            //   8bf9                 | mov                 edi, ecx
            //   8d4df4               | lea                 ecx, [ebp - 0xc]
            //   e8????????           |                     
            //   8d4de8               | lea                 ecx, [ebp - 0x18]
            //   e8????????           |                     

        $sequence_2 = { 50 e8???????? 83661c00 59 59 ff15???????? }
            // n = 6, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   83661c00             | and                 dword ptr [esi + 0x1c], 0
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   ff15????????         |                     

        $sequence_3 = { 5e c3 56 8bf1 33c9 33c0 40 }
            // n = 7, score = 100
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   33c9                 | xor                 ecx, ecx
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax

        $sequence_4 = { 75ca 8b06 881c07 8b4514 8938 c745e401000000 8b35???????? }
            // n = 7, score = 100
            //   75ca                 | jne                 0xffffffcc
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   881c07               | mov                 byte ptr [edi + eax], bl
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   8938                 | mov                 dword ptr [eax], edi
            //   c745e401000000       | mov                 dword ptr [ebp - 0x1c], 1
            //   8b35????????         |                     

        $sequence_5 = { e8???????? 50 8bcb e8???????? 85c0 7423 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   50                   | push                eax
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7423                 | je                  0x25

        $sequence_6 = { 83feff 757f 8d4ddc e8???????? }
            // n = 4, score = 100
            //   83feff               | cmp                 esi, -1
            //   757f                 | jne                 0x81
            //   8d4ddc               | lea                 ecx, [ebp - 0x24]
            //   e8????????           |                     

        $sequence_7 = { 8d4528 68???????? 50 e8???????? 83c410 53 8d455c }
            // n = 7, score = 100
            //   8d4528               | lea                 eax, [ebp + 0x28]
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   53                   | push                ebx
            //   8d455c               | lea                 eax, [ebp + 0x5c]

        $sequence_8 = { 8b4508 59 5f 5e c9 c20c00 56 }
            // n = 7, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   59                   | pop                 ecx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   c9                   | leave               
            //   c20c00               | ret                 0xc
            //   56                   | push                esi

        $sequence_9 = { 53 56 8bf1 57 8d4dec e8???????? 33db }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   57                   | push                edi
            //   8d4dec               | lea                 ecx, [ebp - 0x14]
            //   e8????????           |                     
            //   33db                 | xor                 ebx, ebx

    condition:
        7 of them and filesize < 65536
}