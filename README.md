# dmarc-report-parser

Parser da riga di comando per i report aggregati DMARC (RUA). Legge file `.xml`, `.gz` e `.zip`, singoli o da cartella, e produce un riepilogo, un CSV o un JSON.

Solo libreria standard di Python (3.9+), nessuna dipendenza.

## Uso

```
python dmarc_report_parser.py report.xml.gz
python dmarc_report_parser.py ./reports --format csv > out.csv
python dmarc_report_parser.py ./reports --format json
```

Il riepilogo mostra i messaggi totali, la percentuale di pass/fail DMARC e il dettaglio per IP sorgente.

## Test

```
python -m unittest discover tests
```

## Licenza

MIT, vedi [LICENSE](LICENSE).
