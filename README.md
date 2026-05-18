# Malpedia's yara-signator rules

This repository intends to simplify access to and synchronization of [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)'s automatically generated, code-based YARA rules.

The rules are periodically created by Felix Bilstein, using the tool [YARA-Signator](https://github.com/fxb-cocacoding/yara-signator) - approach described in this [paper](https://journal.cecyf.fr/ojs/index.php/cybin/article/view/24).

The content of the `rules` folder is also identical with what is returned by the respective [Malpedia API call](https://malpedia.caad.fkie.fraunhofer.de/api/get/yara/auto/zip).

They are released under the [CC BY-SA 4.0 license](https://creativecommons.org/licenses/by-sa/4.0/), allowing commercial usage.

## Latest Release: 2026-05-04

Across Malpedia, the current rule set achieves:
```
++++++++++++++++++ Statistics +++++++++++++++++++
Evaluation date:                       2026-05-04
Samples (all):                              16245
Samples (detectable):                        6269
Families:                                    3714
-------------------------------------------------
Families covered by rules:                   1622
Rules without FPs:                           1611
Rules without FNs:                           1519
'Clean' Rules:                               1513
-------------------------------------------------
True Positives:                              5943
False Positives:                               32
True Negatives:                              8510
False Negatives:                              326

-------------------------------------------------
PPV / Precision:                            0.995
TPR / Recall:                               0.948
F1:                                         0.971

```

with no false positives against the [VirusTotal goodware data set](https://blog.virustotal.com/2019/10/test-your-yara-rules-against-goodware.html).
