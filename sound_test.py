import pygame, time, config, os
print("File:", config.SIREN_HIGH_MP3, "exists?", os.path.exists(config.SIREN_HIGH_MP3))
pygame.mixer.init()
pygame.mixer.music.load(config.SIREN_HIGH_MP3)
pygame.mixer.music.play(-1)   # loop 2s
time.sleep(2)
pygame.mixer.music.stop()
print("OK")
