import json
import csv
import random

def safe(text):
    return text.strip().lower().replace(' ', '-')

with open('Adjectives.csv') as csvfile:
    reader = csv.reader(csvfile)

    adjectives = [ safe(row[1]) for row in reader ]

with open('css_color_names.json', 'r') as jsonfile:
    data = json.load(jsonfile)
    color_names = [ safe(color) for color in list(data.keys()) ]

with open('animals.json', 'r') as animals_file:
    animal_names = [ safe(animal) for animal in json.load(animals_file) ]

out = {
    'adjectives': adjectives,
    'colors': color_names,
    'animals': animal_names,
}

print(len(adjectives) * len(color_names) * len(animal_names))

adjective = random.choice(adjectives)
color = random.choice(color_names)
animal = random.choice(animal_names)

print(f'{adjective}-{color}-{animal}')

with open('names.json', 'w') as out_file:
    json.dump(out, out_file, indent=2)
