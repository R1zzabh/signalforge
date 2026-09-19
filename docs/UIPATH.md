# UiPath

Open `uipath/Main.xaml` in UiPath Studio. Keep the FastAPI server at `http://localhost:8000`, use an `alerts.xlsx` workbook with headers matching the alert schema, and run the workflow. The workflow contains read, validation, IOC extraction, retry scope, backend call, processing, severity routing, report, notification, and result-writing stages. Critical paths should pause for analyst approval.
