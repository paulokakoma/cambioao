document.addEventListener('DOMContentLoaded', async () => {
    const SUPABASE_URL = 'https://fgzgrbcvvabcqrqbfljp.supabase.co';
    const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZnemdyYmN2dmFiY3FycWJmbGpwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MTQ0MDM4OTksImV4cCI6MjAyOTk3OTg5OX0.y_s-hKk8Kz1wr-i1yK1wA-sJb2i_G3eWk_1Y2gYh2y4';

    const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

    const visaCardImageContainer = document.getElementById('visa-card-image-container');
    const titleEl = document.getElementById('visa-card-title');
    const descriptionEl = document.getElementById('visa-card-description');
    const acquisitionFeeEl = document.getElementById('visa-card-acquisition-fee');
    const minLoadEl = document.getElementById('visa-card-min-load');
    const advantagesListEl = document.getElementById('visa-card-advantages');
    const howItWorksContainerEl = document.getElementById('visa-card-how-it-works-container');
    const whatsappBtn = document.getElementById('whatsapp-cta-btn');
    const whatsappBtnText = document.getElementById('whatsapp-cta-text');

    function showLoadingState() {
        titleEl.textContent = 'A carregar...';
        descriptionEl.textContent = 'Por favor, aguarde enquanto carregamos os detalhes do cartão.';
        acquisitionFeeEl.textContent = '...';
        minLoadEl.textContent = '...';
        whatsappBtn.classList.add('cursor-not-allowed', 'bg-gray-400');
        whatsappBtn.setAttribute('aria-disabled', 'true');
    }

    function formatCurrency(value, currency = 'AOA') {
        return new Intl.NumberFormat('pt-AO', { style: 'currency', currency }).format(value);
    }

    async function loadVisaData() {
        showLoadingState();

        try {
            const { data, error } = await supabase
                .from('site_settings')
                .select('key, value')
                .like('key', 'visa_%');

            if (error) throw error;

            const settings = data.reduce((acc, { key, value }) => {
                acc[key] = value;
                return acc;
            }, {});

            titleEl.textContent = settings.visa_title || 'Cartão Visa Virtual';
            descriptionEl.textContent = settings.visa_description || 'Adquira já o seu cartão para fazer compras online e em qualquer lugar do mundo.';
            
            acquisitionFeeEl.textContent = settings.visa_acquisition_fee ? formatCurrency(settings.visa_acquisition_fee, 'AOA') : 'N/D';
            minLoadEl.textContent = settings.visa_min_load ? formatCurrency(settings.visa_min_load, 'USD') : 'N/D';

            if (settings.visa_advantages && Array.isArray(settings.visa_advantages)) {
                advantagesListEl.innerHTML = settings.visa_advantages.map(item => `<li>${item}</li>`).join('');
            }

            if (settings.visa_how_it_works && Array.isArray(settings.visa_how_it_works)) {
                howItWorksContainerEl.innerHTML = `
                    <h2 class="text-3xl font-bold text-slate-700 pt-6">Como Funciona?</h2>
                    <ol class="list-decimal pl-6 space-y-2 mt-4">
                        ${settings.visa_how_it_works.map(item => `<li>${item}</li>`).join('')}
                    </ol>
                `;
            }

            if (settings.visa_whatsapp_number) {
                whatsappBtn.href = `https://wa.me/${settings.visa_whatsapp_number}`;
                whatsappBtnText.textContent = 'Pedir Cartão via WhatsApp';
                whatsappBtn.classList.remove('cursor-not-allowed', 'bg-gray-400');
                whatsappBtn.classList.add('bg-green-500', 'hover:bg-green-600');
                whatsappBtn.removeAttribute('aria-disabled');
            }

        } catch (error) {
            console.error('Erro ao carregar dados do cartão Visa:', error);
            descriptionEl.textContent = 'Não foi possível carregar as informações do cartão. Por favor, tente mais tarde.';
        }
    }

    loadVisaData();
});