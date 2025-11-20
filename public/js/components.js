/**
 * Carrega componentes HTML reutilizáveis em elementos designados.
 * Procura por elementos com o atributo `data-include` e carrega o HTML
 * do caminho especificado nesse atributo.
 * 
 * Exemplo de uso no HTML:
 * <footer data-include="/components/_footer.html" class="bg-slate-800 text-slate-400 mt-16 py-8"></footer>
 */
document.addEventListener('DOMContentLoaded', () => {
    const elementsToInclude = document.querySelectorAll('[data-include]');

    elementsToInclude.forEach(async (el) => {
        const path = el.dataset.include;
        if (path) {
            try {
                const response = await fetch(path);
                el.innerHTML = await response.text();
            } catch (error) {
                console.error(`Falha ao carregar o componente de '${path}':`, error);
                el.innerHTML = `<p class="text-red-500 text-center">Erro ao carregar o rodapé.</p>`;
            }
        }
    });
});