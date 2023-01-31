rule win_epsilon_red_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.epsilon_red."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.epsilon_red"
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
        $sequence_0 = { 762c 488d59ff 4989c0 48b8cdcccccccccccccc 4989d1 48f7e6 48c1ea03 }
            // n = 7, score = 200
            //   762c                 | dec                 eax
            //   488d59ff             | add                 esp, 0x60
            //   4989c0               | ret                 
            //   48b8cdcccccccccccccc     | dec    eax
            //   4989d1               | lea                 eax, [0xaa4b0]
            //   48f7e6               | dec                 eax
            //   48c1ea03             | mov                 dword ptr [esp], eax

        $sequence_1 = { 4983f902 770d ba06000000 4531c0 e9???????? 49c1ea02 4c8b642468 }
            // n = 7, score = 200
            //   4983f902             | mov                 dword ptr [esp + 8], ecx
            //   770d                 | dec                 eax
            //   ba06000000           | mov                 ecx, dword ptr [edx]
            //   4531c0               | dec                 eax
            //   e9????????           |                     
            //   49c1ea02             | mov                 eax, dword ptr [edx + 8]
            //   4c8b642468           | jmp                 0x1185

        $sequence_2 = { 77eb 488b5230 488b9aa0000000 4885db 7566 0fb6c1 0f1f4000 }
            // n = 7, score = 200
            //   77eb                 | dec                 eax
            //   488b5230             | mov                 dword ptr [esp + 0xc0], eax
            //   488b9aa0000000       | dec                 eax
            //   4885db               | mov                 dword ptr [esp + 0xc8], edx
            //   7566                 | mov                 byte ptr [esp + 0xd0], bl
            //   0fb6c1               | dec                 eax
            //   0f1f4000             | mov                 dword ptr [esp + 0xa8], ecx

        $sequence_3 = { 49d3e3 4921c3 4d39da 742a 488d0412 488d40ff 4c89c9 }
            // n = 7, score = 200
            //   49d3e3               | mov                 dword ptr [esp + 0x18], eax
            //   4921c3               | nop                 
            //   4d39da               | nop                 
            //   742a                 | dec                 eax
            //   488d0412             | lea                 ecx, [0x213a14]
            //   488d40ff             | dec                 eax
            //   4c89c9               | mov                 dword ptr [esp], ecx

        $sequence_4 = { f20f10442430 f20f110424 e8???????? f20f10442408 488b442410 f20f100d???????? 660f2ec1 }
            // n = 7, score = 200
            //   f20f10442430         | lea                 eax, [0x139795]
            //   f20f110424           | dec                 eax
            //   e8????????           |                     
            //   f20f10442408         | mov                 dword ptr [esp], eax
            //   488b442410           | dec                 eax
            //   f20f100d????????     |                     
            //   660f2ec1             | mov                 dword ptr [esp + 8], 0x1c

        $sequence_5 = { 8844241e 48891c24 488b442430 4889442408 e8???????? 488b442420 c680b600000001 }
            // n = 7, score = 200
            //   8844241e             | dec                 eax
            //   48891c24             | sub                 esp, 0x58
            //   488b442430           | dec                 eax
            //   4889442408           | mov                 dword ptr [esp + 0x50], ebp
            //   e8????????           |                     
            //   488b442420           | dec                 eax
            //   c680b600000001       | lea                 ebp, [esp + 0x50]

        $sequence_6 = { 90 ebbf 48894c2470 48890424 e8???????? 488b542408 488b4c2470 }
            // n = 7, score = 200
            //   90                   | dec                 eax
            //   ebbf                 | mov                 dword ptr [esp + 0x10], esi
            //   48894c2470           | dec                 eax
            //   48890424             | mov                 eax, dword ptr [esp + 0x30]
            //   e8????????           |                     
            //   488b542408           | dec                 eax
            //   488b4c2470           | mov                 ebx, dword ptr [esp + 0x1d8]

        $sequence_7 = { 65488b0c2528000000 488b8900000000 483b6110 0f8619010000 4883ec48 48896c2440 488d6c2440 }
            // n = 7, score = 200
            //   65488b0c2528000000     | mov    ecx, dword ptr [esp + 0x38]
            //   488b8900000000       | dec                 eax
            //   483b6110             | mov                 dword ptr [esp + 0x20], ecx
            //   0f8619010000         | dec                 eax
            //   4883ec48             | mov                 dword ptr [esp + 0x28], ecx
            //   48896c2440           | dec                 eax
            //   488d6c2440           | mov                 ecx, dword ptr [ecx + 0x18]

        $sequence_8 = { ebe6 0fbae008 73a8 ebaf 4889442418 e8???????? 488b0424 }
            // n = 7, score = 200
            //   ebe6                 | dec                 eax
            //   0fbae008             | lea                 ecx, [esp + 0xa8]
            //   73a8                 | dec                 eax
            //   ebaf                 | mov                 dword ptr [esp + 0x18], ecx
            //   4889442418           | dec                 eax
            //   e8????????           |                     
            //   488b0424             | mov                 dword ptr [esp + 0x20], 4

        $sequence_9 = { 48c744242000000000 c744242800000000 488d4c2460 48894c2430 0f57c0 0f11442438 e8???????? }
            // n = 7, score = 200
            //   48c744242000000000     | dec    eax
            //   c744242800000000     | mov                 ebx, dword ptr [esp + 0x108]
            //   488d4c2460           | dec                 eax
            //   48894c2430           | mov                 dword ptr [esp + 0x148], ebx
            //   0f57c0               | dec                 eax
            //   0f11442438           | mov                 ebx, dword ptr [esp + 0x50]
            //   e8????????           |                     

    condition:
        7 of them and filesize < 5075968
}