rule win_ati_agent_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.ati_agent."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ati_agent"
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
        $sequence_0 = { 488bb424d8070000 488b8c24b0070000 4833cc e8???????? }
            // n = 4, score = 100
            //   488bb424d8070000     | dec                 eax
            //   488b8c24b0070000     | sub                 esp, 0x28
            //   4833cc               | dec                 eax
            //   e8????????           |                     

        $sequence_1 = { 4863ca 8a44191c 42888401d0e70000 ffc2 }
            // n = 4, score = 100
            //   4863ca               | inc                 cl
            //   8a44191c             | xor                 al, 0x6e
            //   42888401d0e70000     | inc                 edx
            //   ffc2                 | movzx               eax, byte ptr [edx + eax]

        $sequence_2 = { e8???????? c70016000000 e8???????? eb40 4c8d2521c30000 488b0d???????? e9???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   c70016000000         | dec                 eax
            //   e8????????           |                     
            //   eb40                 | and                 dword ptr [esp + 0x20], 0
            //   4c8d2521c30000       | dec                 eax
            //   488b0d????????       |                     
            //   e9????????           |                     

        $sequence_3 = { ff15???????? 85c0 0f85f7000000 488b4c2458 488d442450 488d9424f0000000 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   85c0                 | lea                 ecx, dword ptr [0xbf67]
            //   0f85f7000000         | dec                 eax
            //   488b4c2458           | mov                 ecx, dword ptr [ecx + eax*8]
            //   488d442450           | inc                 esp
            //   488d9424f0000000     | mov                 dword ptr [esp + 0x44], edi

        $sequence_4 = { ff15???????? 488d1508a20000 488bce 488905???????? ff15???????? 488bc8 ff15???????? }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   488d1508a20000       | je                  0x255
            //   488bce               | dec                 eax
            //   488905????????       |                     
            //   ff15????????         |                     
            //   488bc8               | sub                 esp, 0x28
            //   ff15????????         |                     

        $sequence_5 = { 85c0 7460 488d0df5130000 ff15???????? 8905???????? }
            // n = 5, score = 100
            //   85c0                 | dec                 ecx
            //   7460                 | mov                 ecx, ebx
            //   488d0df5130000       | mov                 byte ptr [esp + 0x2f], 0
            //   ff15????????         |                     
            //   8905????????         |                     

        $sequence_6 = { eb2b 83f8ff 7526 4c8d253b6a0000 }
            // n = 4, score = 100
            //   eb2b                 | inc                 ebp
            //   83f8ff               | xor                 ecx, ecx
            //   7526                 | dec                 eax
            //   4c8d253b6a0000       | lea                 edx, dword ptr [esp + 0xf0]

        $sequence_7 = { 4883c420 5f c3 48895c2408 4889742410 48897c2418 4154 }
            // n = 7, score = 100
            //   4883c420             | lock dec            dword ptr [ecx]
            //   5f                   | jne                 0xd0
            //   c3                   | dec                 eax
            //   48895c2408           | mov                 ecx, dword ptr [esi + 0xb8]
            //   4889742410           | dec                 ecx
            //   48897c2418           | cmp                 ecx, esp
            //   4154                 | je                  0xd0

        $sequence_8 = { 488b4c2438 8bd8 b802000000 85db 0f45d8 ff15???????? 85db }
            // n = 7, score = 100
            //   488b4c2438           | dec                 eax
            //   8bd8                 | lea                 ebp, dword ptr [0xa1a1]
            //   b802000000           | jne                 0x1e1
            //   85db                 | dec                 eax
            //   0f45d8               | lea                 eax, dword ptr [0x8e48]
            //   ff15????????         |                     
            //   85db                 | dec                 esp

        $sequence_9 = { 6689444c3e 4883f905 72e5 488b15???????? 6644894c244a 498bc9 41bae5ff0000 }
            // n = 7, score = 100
            //   6689444c3e           | mov                 al, byte ptr [edi + edx + 0x4c]
            //   4883f905             | sete                al
            //   72e5                 | ret                 
            //   488b15????????       |                     
            //   6644894c244a         | dec                 eax
            //   498bc9               | mov                 dword ptr [esp + 8], ebx
            //   41bae5ff0000         | push                edi

    condition:
        7 of them and filesize < 172032
}