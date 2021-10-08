rule win_isr_stealer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.isr_stealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.isr_stealer"
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
        $sequence_0 = { fb b05e 2bc1 e8???????? 661e }
            // n = 5, score = 200
            //   fb                   | sti                 
            //   b05e                 | mov                 al, 0x5e
            //   2bc1                 | sub                 eax, ecx
            //   e8????????           |                     
            //   661e                 | push                ds

        $sequence_1 = { 08ac22c115978d 0e e8???????? 07 }
            // n = 4, score = 200
            //   08ac22c115978d       | or                  byte ptr [edx - 0x7268ea3f], ch
            //   0e                   | push                cs
            //   e8????????           |                     
            //   07                   | pop                 es

        $sequence_2 = { 1c8b 53 2456 2bd1 807e6543 }
            // n = 5, score = 200
            //   1c8b                 | sbb                 al, 0x8b
            //   53                   | push                ebx
            //   2456                 | and                 al, 0x56
            //   2bd1                 | sub                 edx, ecx
            //   807e6543             | cmp                 byte ptr [esi + 0x65], 0x43

        $sequence_3 = { 46 1e 301b 15c2c8c807 d6 12d8 }
            // n = 6, score = 200
            //   46                   | inc                 esi
            //   1e                   | push                ds
            //   301b                 | xor                 byte ptr [ebx], bl
            //   15c2c8c807           | adc                 eax, 0x7c8c8c2
            //   d6                   | salc                
            //   12d8                 | adc                 bl, al

        $sequence_4 = { 8d16 b205 07 d32cb6 08ac22c115978d 0e e8???????? }
            // n = 7, score = 200
            //   8d16                 | lea                 edx, dword ptr [esi]
            //   b205                 | mov                 dl, 5
            //   07                   | pop                 es
            //   d32cb6               | shr                 dword ptr [esi + esi*4], cl
            //   08ac22c115978d       | or                  byte ptr [edx - 0x7268ea3f], ch
            //   0e                   | push                cs
            //   e8????????           |                     

        $sequence_5 = { a7 8d16 b205 07 d32cb6 08ac22c115978d }
            // n = 6, score = 200
            //   a7                   | cmpsd               dword ptr [esi], dword ptr es:[edi]
            //   8d16                 | lea                 edx, dword ptr [esi]
            //   b205                 | mov                 dl, 5
            //   07                   | pop                 es
            //   d32cb6               | shr                 dword ptr [esi + esi*4], cl
            //   08ac22c115978d       | or                  byte ptr [edx - 0x7268ea3f], ch

        $sequence_6 = { 07 fb b05e 2bc1 e8???????? }
            // n = 5, score = 200
            //   07                   | pop                 es
            //   fb                   | sti                 
            //   b05e                 | mov                 al, 0x5e
            //   2bc1                 | sub                 eax, ecx
            //   e8????????           |                     

        $sequence_7 = { 8d16 b205 07 d32cb6 08ac22c115978d 0e }
            // n = 6, score = 200
            //   8d16                 | lea                 edx, dword ptr [esi]
            //   b205                 | mov                 dl, 5
            //   07                   | pop                 es
            //   d32cb6               | shr                 dword ptr [esi + esi*4], cl
            //   08ac22c115978d       | or                  byte ptr [edx - 0x7268ea3f], ch
            //   0e                   | push                cs

        $sequence_8 = { 07 d32cb6 08ac22c115978d 0e e8???????? }
            // n = 5, score = 200
            //   07                   | pop                 es
            //   d32cb6               | shr                 dword ptr [esi + esi*4], cl
            //   08ac22c115978d       | or                  byte ptr [edx - 0x7268ea3f], ch
            //   0e                   | push                cs
            //   e8????????           |                     

        $sequence_9 = { e8???????? 07 fb b05e 2bc1 e8???????? 661e }
            // n = 7, score = 200
            //   e8????????           |                     
            //   07                   | pop                 es
            //   fb                   | sti                 
            //   b05e                 | mov                 al, 0x5e
            //   2bc1                 | sub                 eax, ecx
            //   e8????????           |                     
            //   661e                 | push                ds

    condition:
        7 of them and filesize < 540672
}