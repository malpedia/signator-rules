rule win_kleptoparasite_stealer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.kleptoparasite_stealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kleptoparasite_stealer"
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
        $sequence_0 = { 7405 8901 895104 8be5 5d c3 3b0d???????? }
            // n = 7, score = 300
            //   7405                 | je                  7
            //   8901                 | mov                 dword ptr [ecx], eax
            //   895104               | mov                 dword ptr [ecx + 4], edx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   3b0d????????         |                     

        $sequence_1 = { 8901 895104 8be5 5d c3 3b0d???????? }
            // n = 6, score = 300
            //   8901                 | mov                 dword ptr [ecx], eax
            //   895104               | mov                 dword ptr [ecx + 4], edx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   3b0d????????         |                     

        $sequence_2 = { c3 e9???????? 55 8bec 56 e8???????? 8bf0 }
            // n = 7, score = 300
            //   c3                   | ret                 
            //   e9????????           |                     
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   56                   | push                esi
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_3 = { 8901 895104 8be5 5d c3 3b0d???????? 7502 }
            // n = 7, score = 300
            //   8901                 | mov                 dword ptr [ecx], eax
            //   895104               | mov                 dword ptr [ecx + 4], edx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   3b0d????????         |                     
            //   7502                 | jne                 4

        $sequence_4 = { 50 e8???????? cc 55 8bec 56 e8???????? }
            // n = 7, score = 300
            //   50                   | push                eax
            //   e8????????           |                     
            //   cc                   | int3                
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_5 = { 59 c3 6a10 68???????? e8???????? 33ff 897de0 }
            // n = 7, score = 300
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   6a10                 | push                0x10
            //   68????????           |                     
            //   e8????????           |                     
            //   33ff                 | xor                 edi, edi
            //   897de0               | mov                 dword ptr [ebp - 0x20], edi

        $sequence_6 = { e8???????? cc 55 8bec 56 e8???????? 8b7508 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   cc                   | int3                
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]

        $sequence_7 = { 895104 8be5 5d c3 3b0d???????? 7502 }
            // n = 6, score = 300
            //   895104               | mov                 dword ptr [ecx + 4], edx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   3b0d????????         |                     
            //   7502                 | jne                 4

        $sequence_8 = { 7505 b8???????? c3 e9???????? 55 8bec 56 }
            // n = 7, score = 300
            //   7505                 | jne                 7
            //   b8????????           |                     
            //   c3                   | ret                 
            //   e9????????           |                     
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   56                   | push                esi

        $sequence_9 = { 895104 8be5 5d c3 3b0d???????? 7502 f3c3 }
            // n = 7, score = 300
            //   895104               | mov                 dword ptr [ecx + 4], edx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   3b0d????????         |                     
            //   7502                 | jne                 4
            //   f3c3                 | ret                 

    condition:
        7 of them and filesize < 3006464
}