from django.db import models
class urls(models.Model):
    Name=models.CharField(max_length = 20)
    UrlName=models.CharField(max_length=100)
    Output = models.CharField(max_length=20)
    def __str__(self):
        return str(self.Name)
