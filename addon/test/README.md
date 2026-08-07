These tools are copied and slightly adapted from LRNG.

See: [LRNG](https://github.com/smuellerDD/lrng/tree/master/test/sp80090b)

Typically:

```sh
esdm-getrawentropy -s 100000 -o /tmp/data-0001.out
esdm-extractlsb /tmp/data-0001.out /tmp/data-0001.extracted.out 100000 FF
ea_non_iid /tmp/data-0001.extracted.out 8
```
