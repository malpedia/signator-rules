rule win_chiser_client_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.chiser_client."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chiser_client"
        malpedia_rule_date = "20220405"
        malpedia_hash = "ecd38294bd47d5589be5cd5490dc8bb4804afc2a"
        malpedia_version = ""
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
        $sequence_0 = { 663905???????? 7511 0fb705???????? 663b4580 0f84a8000000 8b442450 8985a0010000 }
            // n = 7, score = 100
            //   663905????????       |                     
            //   7511                 | dec                 eax
            //   0fb705????????       |                     
            //   663b4580             | mov                 ecx, ebx
            //   0f84a8000000         | xor                 eax, eax
            //   8b442450             | dec                 eax
            //   8985a0010000         | add                 esp, 0x30

        $sequence_1 = { e8???????? cc 488d4c2438 e8???????? 488d154c940100 488d4c2438 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   cc                   | inc                 esp
            //   488d4c2438           | lea                 edi, dword ptr [eax + 0x6f]
            //   e8????????           |                     
            //   488d154c940100       | inc                 esp
            //   488d4c2438           | lea                 esp, dword ptr [eax + 0x52]
            //   e8????????           |                     

        $sequence_2 = { 0f1f4000 0fb701 6683f820 7406 6683f809 750a ffc7 }
            // n = 7, score = 100
            //   0f1f4000             | mov                 edx, edi
            //   0fb701               | dec                 eax
            //   6683f820             | mov                 ecx, dword ptr [esi + 0x10]
            //   7406                 | dec                 esp
            //   6683f809             | lea                 eax, dword ptr [0x3b4f7]
            //   750a                 | inc                 sp
            //   ffc7                 | mov                 dword ptr [esp + 0x6c], ebp

        $sequence_3 = { 488d0d3b1c0200 ff15???????? 488bc8 488d1533900200 488bd8 ff15???????? 488d153b900200 }
            // n = 7, score = 100
            //   488d0d3b1c0200       | shr                 al, 4
            //   ff15????????         |                     
            //   488bc8               | inc                 esp
            //   488d1533900200       | movzx               esi, byte ptr [esp + 0x58]
            //   488bd8               | dec                 eax
            //   ff15????????         |                     
            //   488d153b900200       | cmp                 edi, 3

        $sequence_4 = { e8???????? 85c0 740a b801000000 e9???????? 8bd5 488bcb }
            // n = 7, score = 100
            //   e8????????           |                     
            //   85c0                 | mov                 byte ptr [edx + 0x1b], al
            //   740a                 | mov                 byte ptr [edx + 0x19], al
            //   b801000000           | mov                 byte ptr [edx + 0x1a], al
            //   e9????????           |                     
            //   8bd5                 | mov                 byte ptr [edx + 0x1b], al
            //   488bcb               | mov                 byte ptr [edx + 0x1c], al

        $sequence_5 = { 85c0 754d ff15???????? 83f87a 7542 8b4c2444 }
            // n = 6, score = 100
            //   85c0                 | test                ecx, ecx
            //   754d                 | je                  0xe8
            //   ff15????????         |                     
            //   83f87a               | dec                 eax
            //   7542                 | lea                 ecx, dword ptr [ebx + 0x50]
            //   8b4c2444             | sub                 edi, dword ptr [ebx + 0x50]

        $sequence_6 = { 448bc7 488bce ff15???????? 85c0 7412 8b7c2430 035c2434 }
            // n = 7, score = 100
            //   448bc7               | dec                 esp
            //   488bce               | mov                 dword ptr [esp + 0x10050], ebp
            //   ff15????????         |                     
            //   85c0                 | dec                 ecx
            //   7412                 | or                  ebp, 0xffffffff
            //   8b7c2430             | test                eax, eax
            //   035c2434             | je                  0x6c0

        $sequence_7 = { 488d05dec80100 488901 488bda c7411003000000 4883c118 e8???????? 488d4f60 }
            // n = 7, score = 100
            //   488d05dec80100       | inc                 ebx
            //   488901               | mov                 byte ptr [edx + 2], cl
            //   488bda               | inc                 ecx
            //   c7411003000000       | movzx               eax, dl
            //   4883c118             | inc                 esp
            //   e8????????           |                     
            //   488d4f60             | movzx               edx, byte ptr [eax + ecx + 0x100]

        $sequence_8 = { 483305???????? 488d156adf0200 488bcb 488905???????? }
            // n = 4, score = 100
            //   483305????????       |                     
            //   488d156adf0200       | ja                  0x172
            //   488bcb               | dec                 eax
            //   488905????????       |                     

        $sequence_9 = { 488bd8 ebdd 4533ff 418bdf 4c8d0d1232ffff }
            // n = 5, score = 100
            //   488bd8               | test                eax, eax
            //   ebdd                 | jne                 0x2fd
            //   4533ff               | dec                 eax
            //   418bdf               | lea                 eax, dword ptr [0x3da67]
            //   4c8d0d1232ffff       | dec                 eax

    condition:
        7 of them and filesize < 714752
}