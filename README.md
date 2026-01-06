# Malpedia's yara-signator rules

This repository intends to simplify access to and synchronization of [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)'s automatically generated, code-based YARA rules.

The rules are periodically created by Felix Bilstein, using the tool [YARA-Signator](https://github.com/fxb-cocacoding/yara-signator) - approach described in this [paper](https://journal.cecyf.fr/ojs/index.php/cybin/article/view/24).

The content of the `rules` folder is also identical with what is returned by the respective [Malpedia API call](https://malpedia.caad.fkie.fraunhofer.de/api/get/yara/auto/zip).

They are released under the [CC BY-SA 4.0 license](https://creativecommons.org/licenses/by-sa/4.0/), allowing commercial usage.

## Latest Release: 2026-01-06

Across Malpedia, the current rule set achieves:
```
++++++++++++++++++ Statistics +++++++++++++++++++
Evaluation date:                       2026-01-06
Samples (all):                              15849
Samples (detectable):                        6180
Families:                                    3607
-------------------------------------------------
Families covered by rules:                   1595
Rules without FPs:                           1584
Rules without FNs:                           1500
'Clean' Rules:                               1495
-------------------------------------------------
True Positives:                              5883
False Positives:                               37
True Negatives:                              8183
False Negatives:                              297

-------------------------------------------------
PPV / Precision:                            0.994
TPR / Recall:                               0.952
F1:                                         0.972

```

with no false positives against the [VirusTotal goodware data set](https://blog.virustotal.com/2019/10/test-your-yara-rules-against-goodware.html).
