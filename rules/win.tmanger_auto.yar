rule win_tmanger_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.tmanger."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tmanger"
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
        $sequence_0 = { c7411cf8f0564e c7412066b8276e c7412425d933d1 c7412861fdc72a c7412cdf9134d2 }
            // n = 5, score = 300
            //   c7411cf8f0564e       | lea                 eax, [ebp - 0x3ec]
            //   c7412066b8276e       | lea                 ecx, [ebp - 0x38]
            //   c7412425d933d1       | mov                 byte ptr [ebp - 4], 0x14
            //   c7412861fdc72a       | lea                 eax, [esi + 0x19c]
            //   c7412cdf9134d2       | push                eax

        $sequence_1 = { c7411cf8f0564e c7412066b8276e c7412425d933d1 c7412861fdc72a c7412cdf9134d2 c74130324d251d }
            // n = 6, score = 300
            //   c7411cf8f0564e       | xor                 eax, eax
            //   c7412066b8276e       | mov                 dword ptr [ebp - 0x34], 0x574ebc
            //   c7412425d933d1       | mov                 ecx, esi
            //   c7412861fdc72a       | mov                 ecx, ebx
            //   c7412cdf9134d2       | call                esi
            //   c74130324d251d       | inc                 edi

        $sequence_2 = { c741651f013f62 c74169388b8e92 c7416d9b14f6a0 c7417180fcd6bb c74175d7401d36 }
            // n = 5, score = 300
            //   c741651f013f62       | mov                 ecx, dword ptr [ebp - 0x3a8]
            //   c74169388b8e92       | mov                 byte ptr [ebp - 4], 0x42
            //   c7416d9b14f6a0       | lea                 ecx, [ecx - 0x10]
            //   c7417180fcd6bb       | lea                 ecx, [ebp - 0x38]
            //   c74175d7401d36       | mov                 ecx, dword ptr [ebp - 0x3a8]

        $sequence_3 = { c741510f9f2997 c7415565449eac c741594d68b93a c7415d382cd7bd c74161d47bdb0f }
            // n = 5, score = 300
            //   c741510f9f2997       | lea                 ecx, [ebp - 0x38]
            //   c7415565449eac       | mov                 ecx, dword ptr [ebp - 0x3c4]
            //   c741594d68b93a       | mov                 byte ptr [ebp - 4], 0x1f
            //   c7415d382cd7bd       | lea                 ecx, [ecx - 0x10]
            //   c74161d47bdb0f       | lea                 ecx, [ebp - 0x38]

        $sequence_4 = { c741651f013f62 c74169388b8e92 c7416d9b14f6a0 c7417180fcd6bb c74175d7401d36 c7417958fffa19 66c7417dfc19 }
            // n = 7, score = 300
            //   c741651f013f62       | mov                 ecx, dword ptr [ebp + 0x18]
            //   c74169388b8e92       | sub                 ecx, dword ptr [ebp + 0x10]
            //   c7416d9b14f6a0       | mov                 eax, dword ptr [ebp + 0x14]
            //   c7417180fcd6bb       | lea                 ecx, [ebp - 0x74]
            //   c74175d7401d36       | lea                 ecx, [ebp - 0x6c]
            //   c7417958fffa19       | mov                 dword ptr [ebp - 0x6c], 0x574ebc
            //   66c7417dfc19         | ret                 0x24

        $sequence_5 = { c74149ff663a9d c7414dd22a7e91 c741510f9f2997 c7415565449eac c741594d68b93a c7415d382cd7bd c74161d47bdb0f }
            // n = 7, score = 300
            //   c74149ff663a9d       | mov                 byte ptr [ebp - 4], 1
            //   c7414dd22a7e91       | mov                 dword ptr [ebp - 0x80], 0x574eac
            //   c741510f9f2997       | jmp                 0x1461
            //   c7415565449eac       | mov                 eax, dword ptr [ebp - 0x60]
            //   c741594d68b93a       | mov                 esi, dword ptr [ebp - 0x34]
            //   c7415d382cd7bd       | lea                 ecx, [ebp - 0x80]
            //   c74161d47bdb0f       | mov                 dword ptr [ebp - 0x80], 0x574ebc

        $sequence_6 = { c741594d68b93a c7415d382cd7bd c74161d47bdb0f c741651f013f62 c74169388b8e92 c7416d9b14f6a0 }
            // n = 6, score = 300
            //   c741594d68b93a       | mov                 ecx, esi
            //   c7415d382cd7bd       | movzx               eax, word ptr [esp + 0x84]
            //   c74161d47bdb0f       | cmp                 eax, ebx
            //   c741651f013f62       | jne                 0x37a
            //   c74169388b8e92       | dec                 esp
            //   c7416d9b14f6a0       | lea                 ecx, [0x21138]

        $sequence_7 = { c74114c2a02ab0 c74118d95dc845 c7411cf8f0564e c7412066b8276e c7412425d933d1 }
            // n = 5, score = 300
            //   c74114c2a02ab0       | push                eax
            //   c74118d95dc845       | lea                 eax, [ebp - 0x3a4]
            //   c7411cf8f0564e       | push                eax
            //   c7412066b8276e       | lea                 ecx, [ebp - 0x38]
            //   c7412425d933d1       | mov                 byte ptr [ebp - 4], 0

        $sequence_8 = { c74118d95dc845 c7411cf8f0564e c7412066b8276e c7412425d933d1 c7412861fdc72a c7412cdf9134d2 }
            // n = 6, score = 300
            //   c74118d95dc845       | call                esi
            //   c7411cf8f0564e       | mov                 esi, dword ptr [ebp - 0x308]
            //   c7412066b8276e       | mov                 eax, dword ptr [ebp - 0x318]
            //   c7412425d933d1       | mov                 ecx, esi
            //   c7412861fdc72a       | mov                 ecx, ebx
            //   c7412cdf9134d2       | call                esi

        $sequence_9 = { c741594d68b93a c7415d382cd7bd c74161d47bdb0f c741651f013f62 c74169388b8e92 c7416d9b14f6a0 c7417180fcd6bb }
            // n = 7, score = 300
            //   c741594d68b93a       | mov                 esi, dword ptr [eax + 0x68]
            //   c7415d382cd7bd       | mov                 dword ptr [ebp - 0x78], 0x574ebc
            //   c74161d47bdb0f       | mov                 dword ptr [ebp - 0x80], 0x574e9c
            //   c741651f013f62       | lea                 ecx, [ebp - 0x80]
            //   c74169388b8e92       | lea                 ecx, [ebp - 0x78]
            //   c7416d9b14f6a0       | lea                 ecx, [ebp - 0x7c]
            //   c7417180fcd6bb       | mov                 edx, dword ptr [esp + 8]

    condition:
        7 of them and filesize < 8252416
}