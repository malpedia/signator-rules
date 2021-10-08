rule win_moure_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.moure."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.moure"
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
        $sequence_0 = { 836b8741 054ccb0558 c3 8458c5 803442bf 002a }
            // n = 6, score = 100
            //   836b8741             | sub                 dword ptr [ebx - 0x79], 0x41
            //   054ccb0558           | add                 eax, 0x5805cb4c
            //   c3                   | ret                 
            //   8458c5               | test                byte ptr [eax - 0x3b], bl
            //   803442bf             | xor                 byte ptr [edx + eax*2], 0xbf
            //   002a                 | add                 byte ptr [edx], ch

        $sequence_1 = { 57 c1c7c2 f7d7 5f 3d80000000 0f8526000000 }
            // n = 6, score = 100
            //   57                   | push                edi
            //   c1c7c2               | rol                 edi, -0x3e
            //   f7d7                 | not                 edi
            //   5f                   | pop                 edi
            //   3d80000000           | cmp                 eax, 0x80
            //   0f8526000000         | jne                 0x2c

        $sequence_2 = { 8bce 85c0 7c20 8365fc00 8d45fc 50 007510 }
            // n = 7, score = 100
            //   8bce                 | mov                 ecx, esi
            //   85c0                 | test                eax, eax
            //   7c20                 | jl                  0x22
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   8d45fc               | lea                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax
            //   007510               | add                 byte ptr [ebp + 0x10], dh

        $sequence_3 = { 008b0069eac9 7000 98 00d1 670076d8 }
            // n = 5, score = 100
            //   008b0069eac9         | add                 byte ptr [ebx - 0x36159700], cl
            //   7000                 | jo                  2
            //   98                   | cwde                
            //   00d1                 | add                 cl, dl
            //   670076d8             | add                 byte ptr [bp - 0x28], dh

        $sequence_4 = { f7d7 81c7f8ffffff 2be7 5f 55 8bec }
            // n = 6, score = 100
            //   f7d7                 | not                 edi
            //   81c7f8ffffff         | add                 edi, 0xfffffff8
            //   2be7                 | sub                 esp, edi
            //   5f                   | pop                 edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp

        $sequence_5 = { e8???????? 663bf8 5f 751c 8bcb e8???????? }
            // n = 6, score = 100
            //   e8????????           |                     
            //   663bf8               | cmp                 di, ax
            //   5f                   | pop                 edi
            //   751c                 | jne                 0x1e
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     

        $sequence_6 = { 8325????????00 8d4514 50 007514 007510 007518 }
            // n = 6, score = 100
            //   8325????????00       |                     
            //   8d4514               | lea                 eax, dword ptr [ebp + 0x14]
            //   50                   | push                eax
            //   007514               | add                 byte ptr [ebp + 0x14], dh
            //   007510               | add                 byte ptr [ebp + 0x10], dh
            //   007518               | add                 byte ptr [ebp + 0x18], dh

        $sequence_7 = { 2be7 5f 83c410 51 }
            // n = 4, score = 100
            //   2be7                 | sub                 esp, edi
            //   5f                   | pop                 edi
            //   83c410               | add                 esp, 0x10
            //   51                   | push                ecx

        $sequence_8 = { 33c7 5e 03c6 2bc2 58 }
            // n = 5, score = 100
            //   33c7                 | xor                 eax, edi
            //   5e                   | pop                 esi
            //   03c6                 | add                 eax, esi
            //   2bc2                 | sub                 eax, edx
            //   58                   | pop                 eax

        $sequence_9 = { 81c1f8ffffff 2be1 59 54 51 54 }
            // n = 6, score = 100
            //   81c1f8ffffff         | add                 ecx, 0xfffffff8
            //   2be1                 | sub                 esp, ecx
            //   59                   | pop                 ecx
            //   54                   | push                esp
            //   51                   | push                ecx
            //   54                   | push                esp

    condition:
        7 of them and filesize < 188416
}