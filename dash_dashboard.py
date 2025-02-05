# Import necessary modules
import dash
import pandas as pd
import plotly.express as px
from dash import dcc, html
from dash.dependencies import Input, Output

# Function to load logs from CSV
def load_logs(log_file):
    return pd.read_csv(log_file, parse_dates=["Timestamp"])

# Initialize Dash
app = dash.Dash(__name__)

# Layout definition
app.layout = html.Div([
    html.H1("SSH Honeypot Dashboard"),
    dcc.Graph(id="attack-frequency"),
    dcc.Graph(id="top-usernames"),
    dcc.Graph(id="top-passwords"),
    dcc.Graph(id="geo-map"),  # New map visualization
    dcc.Interval(id="interval-component", interval=60 * 1000, n_intervals=0)  # Refresh every minute
])

# Define callbacks
@app.callback(
    [Output("attack-frequency", "figure"),
     Output("top-usernames", "figure"),
     Output("top-passwords", "figure"),
     Output("geo-map", "figure")],  # Add map output
    [Input("interval-component", "n_intervals")]
)
def update_dashboard(n):
    df = load_logs("honeypot_logs.csv")

    # Attack frequency over time
    attack_freq = df.set_index("Timestamp").resample("H").size().reset_index(name="Attempts")
    freq_fig = px.line(attack_freq, x="Timestamp", y="Attempts", title="SSH Attack Frequency Over Time")

    # Top usernames
    top_usernames = df["Username"].value_counts().head(10).reset_index()
    top_usernames.columns = ["Username", "Attempts"]
    username_fig = px.bar(top_usernames, x="Username", y="Attempts", title="Top 10 Usernames Attempted")

    # Top passwords
    top_passwords = df["Password"].value_counts().head(10).reset_index()
    top_passwords.columns = ["Password", "Attempts"]
    password_fig = px.bar(top_passwords, x="Password", y="Attempts", title="Top 10 Passwords Attempted")

    # Geolocation Map
    geo_df = df.dropna(subset=["Latitude", "Longitude"])  # Remove empty locations
    geo_fig = px.scatter_mapbox(
        geo_df, lat="Latitude", lon="Longitude", hover_name="IP", hover_data=["Country", "City", "Username"],
        title="Geographical Distribution of Attackers",
        mapbox_style="open-street-map", zoom=1  # Adjust zoom level as needed
    )

    return freq_fig, username_fig, password_fig, geo_fig

# Run the Dash app
if __name__ == "__main__":
    app.run_server(debug=True)
