# Malpedia's yara-signator rules

This repository intends to simplify access to and synchronization of [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)'s automatically generated, code-based YARA rules.

The rules are periodically created by Felix Bilstein, using the tool [YARA-Signator](https://github.com/fxb-cocacoding/yara-signator) - approach described in this [paper](https://journal.cecyf.fr/ojs/index.php/cybin/article/view/24).

The content of the `rules` folder is also identical with what is returned by the respective [Malpedia API call](https://malpedia.caad.fkie.fraunhofer.de/api/get/yara/auto/zip).

They are released under the [CC BY-SA 4.0 license](https://creativecommons.org/licenses/by-sa/4.0/), allowing commercial usage.

## Latest Release: 2022-05-16

Across Malpedia, the current rule set achieves:
```
++++++++++++++++++ Statistics +++++++++++++++++++
Evaluation date:                       2022-08-08
Samples (all):                              12147
Samples (detectable):                        4973
Families:                                    2507
-------------------------------------------------
Families covered by rules:                   1160
Rules without FPs:                           1151
Rules without FNs:                           1091
'Clean' Rules:                               1085
-------------------------------------------------
True Positives:                              4794
False Positives:                               32
True Negatives:                              5747
False Negatives:                              179
-------------------------------------------------
PPV / Precision:                            0.993
TPR / Recall:                               0.964
F1:                                         0.978
```

with no false positives against the [VirusTotal goodware data set](https://blog.virustotal.com/2019/10/test-your-yara-rules-against-goodware.html).
