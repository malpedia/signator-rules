rule win_client_maximus_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.client_maximus."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.client_maximus"
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
        $sequence_0 = { 7511 8b5034 85d2 740a 8b4018 85c0 }
            // n = 6, score = 300
            //   7511                 | jne                 0x13
            //   8b5034               | mov                 edx, dword ptr [eax + 0x34]
            //   85d2                 | test                edx, edx
            //   740a                 | je                  0xc
            //   8b4018               | mov                 eax, dword ptr [eax + 0x18]
            //   85c0                 | test                eax, eax

        $sequence_1 = { 881403 75d1 5b 5e }
            // n = 4, score = 300
            //   881403               | mov                 byte ptr [ebx + eax], dl
            //   75d1                 | jne                 0xffffffd3
            //   5b                   | pop                 ebx
            //   5e                   | pop                 esi

        $sequence_2 = { 53 8b5c2414 8b6c2418 6690 }
            // n = 4, score = 300
            //   53                   | push                ebx
            //   8b5c2414             | mov                 ebx, dword ptr [esp + 0x14]
            //   8b6c2418             | mov                 ebp, dword ptr [esp + 0x18]
            //   6690                 | nop                 

        $sequence_3 = { 8b4628 85c0 7535 c70424???????? ff15???????? 83ec04 85c0 }
            // n = 7, score = 300
            //   8b4628               | mov                 eax, dword ptr [esi + 0x28]
            //   85c0                 | test                eax, eax
            //   7535                 | jne                 0x37
            //   c70424????????       |                     
            //   ff15????????         |                     
            //   83ec04               | sub                 esp, 4
            //   85c0                 | test                eax, eax

        $sequence_4 = { 89f0 0fb6c0 0fb61403 88140b 83c101 89fa }
            // n = 6, score = 300
            //   89f0                 | mov                 eax, esi
            //   0fb6c0               | movzx               eax, al
            //   0fb61403             | movzx               edx, byte ptr [ebx + eax]
            //   88140b               | mov                 byte ptr [ebx + ecx], dl
            //   83c101               | add                 ecx, 1
            //   89fa                 | mov                 edx, edi

        $sequence_5 = { 56 53 8b5c2414 8b6c2418 6690 880403 83c001 }
            // n = 7, score = 300
            //   56                   | push                esi
            //   53                   | push                ebx
            //   8b5c2414             | mov                 ebx, dword ptr [esp + 0x14]
            //   8b6c2418             | mov                 ebp, dword ptr [esp + 0x18]
            //   6690                 | nop                 
            //   880403               | mov                 byte ptr [ebx + eax], al
            //   83c001               | add                 eax, 1

        $sequence_6 = { 83ec04 a3???????? c7442404???????? 893424 ff15???????? }
            // n = 5, score = 300
            //   83ec04               | sub                 esp, 4
            //   a3????????           |                     
            //   c7442404????????     |                     
            //   893424               | mov                 dword ptr [esp], esi
            //   ff15????????         |                     

        $sequence_7 = { 90 89c8 0fb63c0b 99 f77c241c }
            // n = 5, score = 300
            //   90                   | nop                 
            //   89c8                 | mov                 eax, ecx
            //   0fb63c0b             | movzx               edi, byte ptr [ebx + ecx]
            //   99                   | cdq                 
            //   f77c241c             | idiv                dword ptr [esp + 0x1c]

        $sequence_8 = { c744240800800000 c744240400000000 890424 8954240c }
            // n = 4, score = 300
            //   c744240800800000     | mov                 dword ptr [esp + 8], 0x8000
            //   c744240400000000     | mov                 dword ptr [esp + 4], 0
            //   890424               | mov                 dword ptr [esp], eax
            //   8954240c             | mov                 dword ptr [esp + 0xc], edx

        $sequence_9 = { 89c8 0fb63c0b 99 f77c241c 89f8 02441500 01c6 }
            // n = 7, score = 300
            //   89c8                 | mov                 eax, ecx
            //   0fb63c0b             | movzx               edi, byte ptr [ebx + ecx]
            //   99                   | cdq                 
            //   f77c241c             | idiv                dword ptr [esp + 0x1c]
            //   89f8                 | mov                 eax, edi
            //   02441500             | add                 al, byte ptr [ebp + edx]
            //   01c6                 | add                 esi, eax

    condition:
        7 of them and filesize < 106496
}