import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
  standalone: true,
  name: 'plural'
})
/**
 * Ce pipe peut être utilisé dans les templates Angular pour pluraliser les chaînes de caractères en fonction d'une valeur numérique.
 * Par exemple, si vous avez une chaîne 'Vous avez x article{s}' et que vous voulez remplacer '{s}' par 's'
 * lorsque le nombre d'articles est supérieur à 1, vous pouvez utiliser ce pipe.
 */
export class PluralPipe implements PipeTransform {
  transform(string: string, value: number, plural: string, singular = ''): string {
    return value > 1 ? string.replace('{s}', plural) : string.replace('{s}', singular);
  }
}
