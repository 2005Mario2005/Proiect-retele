import json
import folium
from folium.plugins import MarkerCluster

with open('harta.json', 'r') as f:
    date = json.load(f)

    def get_color(cat):
        if 'Google' in cat:
            return 'blue'
        elif 'Microsoft' in cat:
            return 'orange'
        elif 'local' in cat:
            return 'green'
        else:
            return 'red'

    harta = folium.Map(location = [45.94, 24.96], zoom_start = 7)
    cluster = MarkerCluster().add_to(harta)

    for primarie in date:
        coord = primarie['coordonate'].replace('Point(','').replace(')', '')
        long, lat = coord.split(' ')

        lat = float(lat)
        long = float(long)

        folium.Marker(
            [lat, long],
            popup = f'localitate: {primarie['nume']}; provider: {primarie['cat']}',
            icon = folium.Icon(color = get_color(primarie['cat'])),
        ).add_to(cluster)

    harta.save('harta.html')