rule win_wscspl_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.wscspl."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wscspl"
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
        $sequence_0 = { 2bc2 51 8bd8 e8???????? 83c404 8b74240c }
            // n = 6, score = 400
            //   2bc2                 | sub                 eax, edx
            //   51                   | push                ecx
            //   8bd8                 | mov                 ebx, eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b74240c             | mov                 esi, dword ptr [esp + 0xc]

        $sequence_1 = { 8b35???????? 668b0d???????? 56 68???????? 68???????? 8935???????? }
            // n = 6, score = 400
            //   8b35????????         |                     
            //   668b0d????????       |                     
            //   56                   | push                esi
            //   68????????           |                     
            //   68????????           |                     
            //   8935????????         |                     

        $sequence_2 = { ff15???????? ff15???????? 6888130000 ff15???????? e8???????? 8a442424 a801 }
            // n = 7, score = 400
            //   ff15????????         |                     
            //   ff15????????         |                     
            //   6888130000           | push                0x1388
            //   ff15????????         |                     
            //   e8????????           |                     
            //   8a442424             | mov                 al, byte ptr [esp + 0x24]
            //   a801                 | test                al, 1

        $sequence_3 = { 83c40c 57 e8???????? 83c404 8935???????? 8b4c2414 8b15???????? }
            // n = 7, score = 400
            //   83c40c               | add                 esp, 0xc
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8935????????         |                     
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   8b15????????         |                     

        $sequence_4 = { 687c230000 68c00b0000 bb???????? e8???????? }
            // n = 4, score = 400
            //   687c230000           | push                0x237c
            //   68c00b0000           | push                0xbc0
            //   bb????????           |                     
            //   e8????????           |                     

        $sequence_5 = { 5f 8935???????? 5e 5d 8b8c2488230000 }
            // n = 5, score = 400
            //   5f                   | pop                 edi
            //   8935????????         |                     
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   8b8c2488230000       | mov                 ecx, dword ptr [esp + 0x2388]

        $sequence_6 = { 75f9 2bc6 50 8d8c241c010000 68???????? }
            // n = 5, score = 400
            //   75f9                 | jne                 0xfffffffb
            //   2bc6                 | sub                 eax, esi
            //   50                   | push                eax
            //   8d8c241c010000       | lea                 ecx, [esp + 0x11c]
            //   68????????           |                     

        $sequence_7 = { c3 53 50 8bcd 8d742414 }
            // n = 5, score = 400
            //   c3                   | ret                 
            //   53                   | push                ebx
            //   50                   | push                eax
            //   8bcd                 | mov                 ecx, ebp
            //   8d742414             | lea                 esi, [esp + 0x14]

        $sequence_8 = { 8b0d???????? 03c3 56 3bc1 }
            // n = 4, score = 400
            //   8b0d????????         |                     
            //   03c3                 | add                 eax, ebx
            //   56                   | push                esi
            //   3bc1                 | cmp                 eax, ecx

        $sequence_9 = { 33c9 8d5c2424 e8???????? bf7c230000 83c414 3bf7 7702 }
            // n = 7, score = 400
            //   33c9                 | xor                 ecx, ecx
            //   8d5c2424             | lea                 ebx, [esp + 0x24]
            //   e8????????           |                     
            //   bf7c230000           | mov                 edi, 0x237c
            //   83c414               | add                 esp, 0x14
            //   3bf7                 | cmp                 esi, edi
            //   7702                 | ja                  4

    condition:
        7 of them and filesize < 901120
}