# GMP Task Report Exporter

`list_tasks.gmp.py` is a `gvm-script` extension that lists GMP tasks and exports findings from each task's most recent completed report to a CSV file.

For each task, it prints the task name, UUID, and last scan end time. When a task has a report ID and scan end time, the script fetches the report and writes findings whose threat level is `High`, `Medium`, or `Low`. Each CSV includes host, port, severity, QoD, NVT details, solution information, references, and task/report identifiers. Multi-line descriptive fields are flattened to a single line.

Tasks with no completed report are listed but not exported. Exported files are written to the current working directory and named using the sanitized task name and scan end time, for example `HGSC-AD-Servers-2026-10-10T00_11_28-05_00.csv`. The CSV header is written even when the report has no findings at the included threat levels. A failure to export one task is reported without preventing the script from continuing with other tasks.

## Requirements

- `gvm-script` from the Greenbone `gvm-tools` package
- Network or local socket access to a GMP service, as configured for the `socket` connection method
- GMP credentials with permission to list tasks and access their reports

## Run

From Bash, set the GMP credentials in environment variables and run the script from the directory where you want the CSV files created:

```bash
export GMP_USERNAME="your-gmp-username"
export GMP_PASSWORD="your-gmp-password"

gvm-script \
  --gmp-username "$GMP_USERNAME" \
  --gmp-password "$GMP_PASSWORD" \
  socket list_tasks.gmp.py
```

The command prints the task summary and reports the name and finding count for each CSV it exports.

## License

This project is released under the 0BSD license. See [LICENSE](LICENSE).