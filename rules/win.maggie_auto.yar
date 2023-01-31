rule win_maggie_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.maggie."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.maggie"
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
        $sequence_0 = { b8ff000000 663b05???????? 7505 e8???????? e8???????? 84c0 }
            // n = 6, score = 300
            //   b8ff000000           | dec                 eax
            //   663b05????????       |                     
            //   7505                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   e8????????           |                     
            //   84c0                 | dec                 eax

        $sequence_1 = { e9???????? ff15???????? 3905???????? 740a b8dd100000 e9???????? }
            // n = 6, score = 300
            //   e9????????           |                     
            //   ff15????????         |                     
            //   3905????????         |                     
            //   740a                 | mov                 eax, dword ptr [ecx]
            //   b8dd100000           | call                dword ptr [eax + 0x10]
            //   e9????????           |                     

        $sequence_2 = { 750a b857000000 e9???????? ff15???????? 3905???????? 740a }
            // n = 6, score = 300
            //   750a                 | test                ebx, ebx
            //   b857000000           | je                  0x156c
            //   e9????????           |                     
            //   ff15????????         |                     
            //   3905????????         |                     
            //   740a                 | dec                 eax

        $sequence_3 = { b857000000 e9???????? ff15???????? 3905???????? }
            // n = 4, score = 300
            //   b857000000           | dec                 eax
            //   e9????????           |                     
            //   ff15????????         |                     
            //   3905????????         |                     

        $sequence_4 = { 750a b857000000 e9???????? ff15???????? 3905???????? 740a b8dd100000 }
            // n = 7, score = 300
            //   750a                 | dec                 eax
            //   b857000000           | mov                 ecx, dword ptr [esp + 0x2a0]
            //   e9????????           |                     
            //   ff15????????         |                     
            //   3905????????         |                     
            //   740a                 | dec                 eax
            //   b8dd100000           | mov                 ecx, dword ptr [ecx]

        $sequence_5 = { e9???????? ff15???????? 3905???????? 740a b8dd100000 }
            // n = 5, score = 300
            //   e9????????           |                     
            //   ff15????????         |                     
            //   3905????????         |                     
            //   740a                 | mov                 dword ptr [ebp - 8], ebx
            //   b8dd100000           | mov                 byte ptr [ebp - 1], bl

        $sequence_6 = { 750f ff15???????? 2d33270000 f7d8 1bc0 }
            // n = 5, score = 300
            //   750f                 | add                 ecx, 0x40
            //   ff15????????         |                     
            //   2d33270000           | dec                 eax
            //   f7d8                 | mov                 ecx, dword ptr [esp + 0x2d0]
            //   1bc0                 | dec                 eax

        $sequence_7 = { 83f8ff 750f ff15???????? 2d33270000 f7d8 1bc0 }
            // n = 6, score = 300
            //   83f8ff               | dec                 eax
            //   750f                 | lea                 eax, [0x57d2]
            //   ff15????????         |                     
            //   2d33270000           | dec                 eax
            //   f7d8                 | lea                 eax, [0x570c]
            //   1bc0                 | dec                 eax

        $sequence_8 = { ff15???????? 83f8ff 750f ff15???????? 2d33270000 f7d8 }
            // n = 6, score = 300
            //   ff15????????         |                     
            //   83f8ff               | mov                 ecx, edx
            //   750f                 | dec                 esp
            //   ff15????????         |                     
            //   2d33270000           | mov                 ebp, dword ptr [esp + 0xb0]
            //   f7d8                 | dec                 eax

        $sequence_9 = { 750f ff15???????? 2d33270000 f7d8 }
            // n = 4, score = 300
            //   750f                 | mov                 dword ptr [ebx + esi + 8], edi
            //   ff15????????         |                     
            //   2d33270000           | dec                 ecx
            //   f7d8                 | mov                 eax, ebx

    condition:
        7 of them and filesize < 611328
}